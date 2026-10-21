from reposhield import java


def make(rule, rel, line, evidence, confidence='medium'):
    # Local stand-in for scanner.finding, which needs the rule registered in scanner.RULES.
    return dict(rule=rule, file=rel, line=line, evidence=evidence, confidence=confidence)


def run(text, rel='app/src/main/java/com/x/api/Demo.java'):
    return java.analyze(text, rel, [], make)


def rules(findings):
    return {f['rule'] for f in findings}


CONTROLLER = '''
package com.x.api;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @GetMapping("/{id}")
    public Order get(@PathVariable Long id) {
        return null;
    }
}
'''


def test_unauthenticated_object_route_gets_rs100_and_rs102():
    endpoints, findings = run(CONTROLLER)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep['path'] == '/api/orders/{id}'
    assert ep['methods'] == ['GET']
    assert ep['framework'] == 'spring-pattern'
    assert ep['authentication'] == 'unknown'
    assert {'RS100', 'RS102'} <= rules(findings)


def test_class_preauthorize_is_hint_with_manual_object_review():
    text = CONTROLLER.replace('@RestController', "@RestController\n@PreAuthorize(\"hasRole('USER')\")")
    endpoints, findings = run(text)
    ep = endpoints[0]
    assert ep['authentication'] == 'hint_found'
    assert ep['authorization'] == 'hint_found'
    assert ep['auth_sources'] == ['local_annotation']
    assert ep['object_authorization'] == 'manual_review'
    assert not ({'RS100', 'RS102'} & rules(findings))


def test_method_permitall_is_public_declared():
    text = CONTROLLER.replace('    @GetMapping("/{id}")', '    @PermitAll\n    @GetMapping("/{id}")')
    endpoints, findings = run(text)
    assert endpoints[0]['authentication'] == 'public_declared'
    assert not ({'RS100', 'RS102'} & rules(findings))


def test_preauthorize_permitall_expression_is_public():
    text = CONTROLLER.replace('    @GetMapping("/{id}")', '    @PreAuthorize("permitAll()")\n    @GetMapping("/{id}")')
    assert run(text)[0][0]['authentication'] == 'public_declared'


def test_request_mapping_method_and_path_composition():
    text = '''
@RestController
@RequestMapping(value = "/api/")
public class ItemController {
    @RequestMapping(method = RequestMethod.POST, path = "items/")
    public void create() {}
    @PutMapping
    public void replace() {}
}
'''
    endpoints, _ = run(text)
    assert [(e['methods'], e['path']) for e in endpoints] == [(['POST'], '/api/items'), (['PUT'], '/api')]


def test_auth_annotation_on_neighbour_method_is_not_borrowed():
    text = '''
@RestController
public class MixController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/a")
    public String a() { return ""; }

    @GetMapping("/b")
    public String b() { return ""; }
}
'''
    endpoints, findings = run(text)
    by_path = {e['path']: e for e in endpoints}
    assert by_path['/a']['authentication'] == 'hint_found'
    assert by_path['/b']['authentication'] == 'unknown'
    assert any(f['rule'] == 'RS100' and f['line'] == 8 for f in findings)


def test_non_controller_and_commented_or_quoted_annotations_do_not_count():
    text = '''
// @RestController
/* @RestController @GetMapping("/c") */
@Service
public class Helper {
    String s = "@GetMapping(\\"/x\\") @CrossOrigin(origins = \\"*\\")";
    @GetMapping("/y")
    public void y() {}
}
'''
    endpoints, findings = run(text)
    assert endpoints == []
    assert not findings


def test_cross_origin_variants_are_rs501():
    for annotation in ['@CrossOrigin()', '@CrossOrigin(origins = "*")', '@CrossOrigin']:
        _, findings = run(f'{annotation}\n@RestController\n@RequestMapping("/x")\npublic class A {{}}\n')
        assert 'RS501' in rules(findings), annotation
    _, findings = run('@CrossOrigin(origins = "https://app.example.com")\n@RestController\npublic class A {}\n')
    assert 'RS501' not in rules(findings)


def test_cors_registry_wildcards_are_rs501():
    text = '''
registry.addMapping("/**").allowedOrigins("*");
config.addAllowedOrigin("*");
config.setAllowedOriginPatterns(List.of()).allowedOriginPatterns("*");
'''
    assert [f['rule'] for f in run(text)[1]].count('RS501') == 3


def test_csrf_disabled_variants_are_rs500():
    snippets = [
        'http.csrf().disable();',
        'http.csrf(AbstractHttpConfigurer::disable);',
        'http.csrf(csrf -> csrf.disable());',
    ]
    for snippet in snippets:
        assert 'RS500' in rules(run(snippet)[1]), snippet
    assert 'RS500' not in rules(run('// http.csrf().disable();\nhttp.csrf(Customizer.withDefaults());')[1])


def test_anyrequest_permitall_is_rs503():
    assert 'RS503' in rules(run('http.authorizeHttpRequests(a -> a.anyRequest().permitAll());')[1])
    assert 'RS503' not in rules(run('http.authorizeHttpRequests(a -> a.anyRequest().authenticated());')[1])


def test_resolve_project_uses_first_matching_java_rule_and_module_scope():
    config = '''
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/api/**").authenticated()
    .anyRequest().authenticated());
'''
    cfg_rel = 'backend/src/main/java/com/x/config/SecurityConfig.java'
    ctrl_rel = 'backend/src/main/java/com/x/api/OrderController.java'
    text = '''
@RestController
public class OrderController {
    @GetMapping("/public/x")
    public String pub() { return ""; }
    @GetMapping("/api/orders/{id}")
    public String one() { return ""; }
}
'''
    endpoints, findings = java.analyze(text, ctrl_rel, [], make)
    findings = java.resolve_project(endpoints, findings, [(cfg_rel, java.security_config(config, cfg_rel))])
    by_path = {e['path']: e for e in endpoints}
    assert by_path['/public/x']['authentication'] == 'public_declared'
    one = by_path['/api/orders/{id}']
    assert one['authentication'] == 'hint_found'
    assert one['auth_sources'] == [f'spring_security:{cfg_rel}']
    assert one['object_authorization'] == 'manual_review'
    assert not any(f['rule'] in {'RS100', 'RS102'} for f in findings)


def test_config_in_other_module_does_not_apply():
    endpoints, findings = java.analyze(CONTROLLER, 'app/src/main/java/com/x/api/OrderController.java', [], make)
    cfg = java.security_config('http.authorizeHttpRequests(a -> a.anyRequest().authenticated());', 'other/src/main/java/SecurityConfig.java')
    java.resolve_project(endpoints, findings, [('other/src/main/java/SecurityConfig.java', cfg)])
    assert endpoints[0]['authentication'] == 'unknown'


def test_security_config_java_dsl_collects_rules_in_order():
    text = '''
http.authorizeHttpRequests(a -> a
    .requestMatchers("/public/**", "/health").permitAll()
    .mvcMatchers("/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated());
'''
    cfg = java.security_config(text, 'SecurityConfig.java')
    assert cfg['rules'] == [('/public/**', 'public', None), ('/health', 'public', None), ('/admin/**', 'protected', None)]
    assert cfg['public'] == ['/public/**', '/health']
    assert cfg['protected'] == [('/admin/**', 'hasRole')]
    assert cfg['authenticated_default'] == 5


def test_security_config_xml_intercept_url_any_attribute_order():
    text = '''<http>
  <!-- <intercept-url pattern="/commented/**" access="permitAll"/> -->
  <intercept-url access="permitAll" pattern="/public/**"/>
  <intercept-url pattern="/admin/**" access="hasRole('ADMIN')"/>
  <intercept-url access="IS_AUTHENTICATED_ANONYMOUSLY" pattern="/anon/**"/>
  <intercept-url pattern="/**" access="isAuthenticated()"/>
</http>'''
    cfg = java.security_config(text, 'backend/src/main/webapp/WEB-INF/security.xml')
    assert cfg['public'] == ['/public/**', '/anon/**']
    assert cfg['protected'] == [('/admin/**', "hasRole('ADMIN')"), ('/**', 'isAuthenticated()')]
    assert cfg['authenticated_default'] == 6
    assert cfg['rules'][0] == ('/public/**', 'public', None)


def test_xml_rules_resolve_controller_in_same_module():
    cfg_rel = 'backend/src/main/webapp/WEB-INF/security.xml'
    cfg = java.security_config('<intercept-url pattern="/**" access="isAuthenticated()"/>', cfg_rel)
    endpoints, findings = java.analyze(CONTROLLER, 'backend/src/main/java/com/x/api/OrderController.java', [], make)
    findings = java.resolve_project(endpoints, findings, [(cfg_rel, cfg)])
    assert endpoints[0]['authentication'] == 'hint_found'
    assert not any(f['rule'] in {'RS100', 'RS102'} for f in findings)


def test_properties_secret_is_redacted_and_placeholders_ignored():
    text = '''spring.datasource.password=s3cretReal99
spring.datasource.username=app
jwt.secret=${JWT_SECRET:changeit}
spring.datasource.hikari.password=${DB_PASS}
spring.mail.password=changeme
# password=ignored
'''
    findings = java.config_secrets(text, 'app/src/main/resources/application.properties', make)
    assert [(f['rule'], f['line']) for f in findings] == [('RS502', 1)]
    assert 's3cretReal99' not in findings[0]['evidence']
    assert findings[0]['evidence'] == 'Configuração de credencial literal: [REDACTED]'


def test_yaml_secret_and_scope_of_file_name():
    text = '''spring:
  datasource:
    password: "abc123xyz"
  security:
    oauth2:
      client-secret: ${CLIENT}
      api-key:
'''
    findings = java.config_secrets(text, 'app/src/main/resources/application-prod.yml', make)
    assert [(f['rule'], f['line']) for f in findings] == [('RS502', 3)]
    assert 'abc123xyz' not in findings[0]['evidence']
    assert java.config_secrets('password=s3cret', 'app/src/main/resources/other.properties', make) == []
