import json
import pytest
from reposhield.scanner import scan, markdown, sarif


@pytest.mark.parametrize('code', [
    'localStorage.setItem(TOKEN_KEY, response.token);',
    'const KEY = "balanco:token"; localStorage.setItem(KEY, value);',
    'sessionStorage.setItem(this.tokenKey, value);',
    'localStorage.setItem(UNKNOWN_KEY, response.accessToken);',
    'localStorage.setItem(\n TOKEN_KEY,\n response.token\n);',
    'window.localStorage.setItem("token", value);',
])
def test_production_storage(tmp_path, code):
    (tmp_path/'auth.service.ts').write_text(code)
    report = scan(tmp_path)
    hits = [f for f in report['findings'] if f['rule'] == 'RS209']
    assert len(hits) == 1
    assert hits[0]['context'] == 'production_or_unknown'


def test_storage_ignores_comments_strings_and_unrelated_values(tmp_path):
    (tmp_path/'app.ts').write_text('''
// localStorage.setItem(TOKEN_KEY, response.token);
/* localStorage.setItem('token', value); */
const example = "localStorage.setItem(TOKEN_KEY, response.token)";
localStorage.setItem('theme', 'dark');
localStorage.setItem('label', 'token');
''')
    assert not any(f['rule'] == 'RS209' for f in scan(tmp_path)['findings'])


def test_storage_location_and_test_context(tmp_path):
    code = '\n'*33+'localStorage.setItem(TOKEN_KEY, response.token);'
    (tmp_path/'auth.service.ts').write_text(code)
    (tmp_path/'auth.interceptor.spec.ts').write_text("localStorage.setItem('token', 'fake');")
    hits = [f for f in scan(tmp_path)['findings'] if f['rule'] == 'RS209']
    assert {(f['file'], f['line'], f['context']) for f in hits} == {
        ('auth.service.ts', 34, 'production_or_unknown'), ('auth.interceptor.spec.ts', 1, 'test')}


def test_controllers_scope_allowanonymous_and_no_borrowed_authorize(tmp_path):
    (tmp_path/'UsersController.cs').write_text('''[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class UsersController : ControllerBase {
 [HttpGet("{id}")]
 public IActionResult Get(int id) { return Ok(); }
 [AllowAnonymous]
 [HttpPost("login")]
 public IActionResult Login() { return Ok(); }
}
[Route("api/open")]
public class OpenController : ControllerBase {
 [HttpGet]
 public IActionResult List() { return Ok(); }
}
''')
    report = scan(tmp_path)
    eps = {e['path']: e for e in report['endpoints']}
    assert eps['/api/Users/{id}']['authentication'] == 'hint_found'
    assert eps['/api/Users/{id}']['authorization'] == 'hint_found'
    assert eps['/api/Users/{id}']['line'] == 4
    assert eps['/api/Users/login']['authentication'] == 'public_declared'
    assert eps['/api/Users/login']['authorization'] == 'unknown'
    assert eps['/api/open/']['authentication'] == 'unknown'
    assert any(f['rule'] == 'RS100' for f in report['findings'])


def test_program_rules_and_minimal_api(tmp_path):
    (tmp_path/'Program.cs').write_text('''
builder.Services.AddCors(o => o.AddPolicy("all", b => b.AllowAnyOrigin()));
options.TokenValidationParameters.ValidateLifetime = false;
handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
app.MapGet("/private", () => "ok").RequireAuthorization();
app.MapGet("/public", () => "ok").AllowAnonymous();
app.MapGet("/unknown", () => "ok");
''')
    report = scan(tmp_path)
    assert {'RS400','RS401','RS402','RS100'} <= {f['rule'] for f in report['findings']}
    eps = {e['path']: e for e in report['endpoints']}
    assert eps['/private']['authentication'] == 'hint_found'
    assert eps['/public']['authentication'] == 'public_declared'
    assert eps['/unknown']['authentication'] == 'unknown'


def test_comments_not_dotnet_evidence(tmp_path):
    (tmp_path/'Program.cs').write_text('''
// options.ValidateLifetime = false;
/* builder.AllowAnyOrigin(); */
var help = "DangerousAcceptAnyServerCertificateValidator";
app.MapGet("/private", () => "RequireAuthorization()");
''')
    report = scan(tmp_path)
    assert not ({'RS400','RS401','RS402'} & {f['rule'] for f in report['findings']})
    assert report['endpoints'][0]['authentication'] == 'unknown'


def test_dotnet_config_secrets_redacted_in_all_formats(tmp_path):
    (tmp_path/'appsettings.json').write_text(json.dumps({
        'ConnectionStrings': {'Default': 'Server=localhost;Password=very-sensitive-pass;Database=test'},
        'Jwt': {'SigningKey': 'very-sensitive-signing-key'}}))
    report = scan(tmp_path)
    assert any(f['rule'] == 'RS403' for f in report['findings'])
    for content in [json.dumps(report), markdown(report), json.dumps(sarif(report))]:
        assert 'very-sensitive-pass' not in content
        assert 'very-sensitive-signing-key' not in content


def test_coverage_explains_dotnet_and_unsupported_source(tmp_path):
    (tmp_path/'Program.cs').write_text('class Program {}')
    (tmp_path/'App.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk.Web"/>')
    (tmp_path/'legacy.vb').write_text('Module Main')
    (tmp_path/'obj').mkdir()
    (tmp_path/'obj'/'generated.cs').write_text('class Generated {}')
    report = scan(tmp_path)
    assert report['coverage']['by_extension'] == {'.cs': 1, '.csproj': 1}
    assert report['coverage']['unsupported_source'] == {'.vb': 1}
    assert report['coverage']['excluded_directories'] == 1
    assert any('Código sem analisador' in reason for reason in report['verdict']['reasons'])


def test_default_scan_never_uses_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError('network attempted')
    monkeypatch.setattr('urllib.request.OpenerDirector.open', forbidden)
    monkeypatch.setattr('http.client.HTTPConnection.connect', forbidden)
    (tmp_path/'Program.cs').write_text('app.MapGet("/", () => "ok");')
    scan(tmp_path)
