from apacheconfig import ApacheConfig


DENY_ONE = 'deny %s;'
DENY_ALL = DENY_ONE % 'all'
ALLOW_ONE = 'allow %s;'
ALLOW_ALL = ALLOW_ONE % 'all'
SATISFY = 'satisfy %s;'
AUTHNAME = 'auth_basic %s;'
AUTHFILE = 'auth_basic_user_file %s;'
PASSTHROUGH = 'try_files $uri $uri/ @handler;'
TEMPLATE = """location %s%s {
    %s

    # Make sure the request gets processed as any other request if it gets through the ACL
    try_files $uri $uri/ @handler;
}
"""


def parse_htaccess(content, location):
    config = ApacheConfig.parse_string(content)
    pieces = []

    for block in config.children:
        acl = handle_directive(block)

        if acl:
            pieces.append(acl)

    global_acl = generate_global_acl(config)
    acl_part = "\n    ".join(pieces + global_acl)

    if acl_part:
        return TEMPLATE % ('', location, acl_part)
        #if location:
        #    return TEMPLATE % ('', location, acl_part)
        #else:
        #    return acl_part

    return ''


def handle_directive(block):
    if len(block.children) <= 0:
        return

    directive = block.name.lower()

    if directive == 'directory':
        return generate_directory_acl(block)
    elif directive == 'directorymatch':
        return generate_directorymatch_acl(block)
    elif directive == 'filesmatch':
        return generate_filesmatch_acl(block)
    elif directive == 'files':
        return generate_files_acl(block)


def generate_acl_for_children(children):
    acl = []

    for child in children:
        child_block = handle_directive(child)

        if child_block:
            acl.append(child_block)
    return acl


def generate_global_acl(config):
    apache_policy = determine_policy(config)
    return generate_nginx_acl(apache_policy, config)


def generate_directory_acl(block):
    # Directory may contain FilesMatch or Files (or even nested Directories?)
    acl = generate_acl_for_children(block.children)

    modifier, location = parse_modifier_and_location(block.values)
    return generate_acl_for_config_block(block, location, extra_blocks=acl, modifier=modifier)


def generate_directorymatch_acl(block):
    # DirectoryMatch may contain FilesMatch or Files (or even nested Directories?)
    acl = generate_acl_for_children(block.children)

    location = "".join(block.values).strip('"')
    return generate_acl_for_config_block(block, location, extra_blocks=acl, modifier='~ ')


def generate_filesmatch_acl(block):
    location = "".join(block.values).strip('"')
    return generate_acl_for_config_block(block, location, modifier='~ ')


def generate_files_acl(block):
    modifier, location = parse_modifier_and_location(block.values)
    return generate_acl_for_config_block(block, location, modifier=modifier)


def generate_acl_for_config_block(block, location, extra_blocks=None, modifier=None):
    nginx_acl = extra_blocks if extra_blocks is not None else []

    apache_policy = determine_policy(block)
    nginx_acl += generate_nginx_acl(apache_policy, block)

    return create_location(location, nginx_acl, modifier=modifier)


def parse_modifier_and_location(values):
    # If original value was a regexp, conversion is simple
    if values[0] == '~':
        location = "".join(values[1:]).strip('"')
        modifier = '~ '
    else:
        modifier = ''
        location = "".join(values).strip('"')

        # If original value used wildcard string, we try to convert them to a regexp
        if '*' in location or '?' in location:
            modifier = '~ '
            location = translate_wildcard_string_to_regexp(location)

    return modifier, location


def create_location(location, content, modifier=None):
    if modifier is None:
        modifier = ''

    lines = "\n    ".join(content)

    return TEMPLATE % (modifier, location, lines)


def determine_policy(block):
    policy = find_directives(block, 'order')

    if len(policy) > 0:
        return "".join(policy[0].values).lower()
    else:
        return None


def generate_nginx_acl(policy, block):

    allows = find_allow_directives(block)
    denies = find_deny_directives(block)
    satisfies = find_satisfy_directives(block)
    auths = find_auth_directives(block)

    if policy == 'allow,deny':
        acl = handle_allow_first_deny_later_policy(allows, denies)
    else:
        # deny,allow is default
        acl = handle_deny_first_allow_later_policy(denies, allows)

    acl += handle_auth_directives(auths)
    acl += [SATISFY % s.values[0].lower() for s in satisfies]
    return acl


# Allow,Deny
#     First, all Allow directives are evaluated; at least one must match,
#     or the request is rejected. Next, all Deny directives are evaluated.
#     If any matches, the request is rejected. Last, any requests which do
#     not match an Allow or a Deny directive are denied by default.
# https://httpd.apache.org/docs/current/mod/mod_access_compat.html#order
def handle_allow_first_deny_later_policy(allows, denies):
    acl = []

    # First list denies, because Apache's mod_access always checks
    # denies, even if the request also matched an allow
    acl += [DENY_ONE % d.values[1].lower() for d in denies]

    # Then add access
    acl += [ALLOW_ONE % a.values[1].lower() for a in allows]

    # Always finish with deny all to enforce default behavior of denying access
    if not DENY_ALL in acl and not ALLOW_ALL in acl:
        acl += [DENY_ALL]

    return acl


# Deny,Allow
#     First, all Deny directives are evaluated; if any match, the request
#     is denied unless it also matches an Allow directive. Any requests
#     which do not match any Allow or Deny directives are permitted.
# https://httpd.apache.org/docs/current/mod/mod_access_compat.html#order
def handle_deny_first_allow_later_policy(denies, allows):
    acl = []

    # First list allows, because Apache's mod_access always checks
    # allows, even if the request also matched a deny
    acl += [ALLOW_ONE % a.values[1].lower() for a in allows]

    # Then add denies
    acl += [DENY_ONE % d.values[1].lower() for d in denies]
    return acl


def handle_auth_directives(auths):
    acl = []

    for auth in auths:
        if auth.name == 'authname':
            acl.append(AUTHNAME % " ".join(auth.values))

        elif auth.name == 'authuserfile':
            acl.append(AUTHFILE % "".join(auth.values))

        elif auth.name == 'authtype' and "".join(auth.values).lower() != 'basic':
            raise Exception("AuthType %s not supported" % "".join(auth.values))

        elif auth.name == 'authbasicprovider' and "".join(auth.values).lower() != 'file':
            raise Exception("AuthBasicProvider %s not supported" % "".join(auth.values))

    # TODO: allow access if "Require valid-user" is not present?
    return acl


def find_directives(block, type):
    return block.findall(type)


def find_allow_directives(block):
    return find_directives(block, 'allow')


def find_deny_directives(block):
    return find_directives(block, 'deny')


def find_satisfy_directives(block):
    return find_directives(block, 'satisfy')


def find_auth_directives(block):
    return find_directives(block, 'authname') + \
        find_directives(block, 'authuserfile') + \
        find_directives(block, 'authtype') + \
        find_directives(block, 'authbasicprovider')


def translate_wildcard_string_to_regexp(subject):
    # Add begin and end tags to regex
    subject = '^' + subject + '$'

    # Dots need to be escaped
    subject = subject.replace('.', '\.')

    # Replace * with .* (or .*? => how about greediness? TODO)
    subject = subject.replace('*', '.*')

    # Replace ? with .
    subject = subject.replace('?', '.')

    return subject
