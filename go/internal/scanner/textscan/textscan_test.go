package textscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func findingsByID(findings []evidence.Evidence) map[string][]evidence.Evidence {
	out := map[string][]evidence.Evidence{}
	for _, f := range findings {
		out[f.ID] = append(out[f.ID], f)
	}
	return out
}

func TestGoRules_DetectSQLInjection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.go", `package x
func a(db *sql.DB, id int) { db.Query("SELECT * FROM u WHERE id = ?", id) }`)
	writeFile(t, dir, "bad.go", `package x
func b(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = " + id) }`)

	got, err := Scan(dir, GoRules())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	by := findingsByID(got)
	if len(by["GO_SQL_INJECTION"]) != 1 {
		t.Errorf("GO_SQL_INJECTION = %d findings; want 1: %+v", len(by["GO_SQL_INJECTION"]), by["GO_SQL_INJECTION"])
	}
}

func TestGoRules_DetectAWSKeyLiteral(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", `package x
var Key = "AKIA1234567890ABCDEF"`)
	got, _ := Scan(dir, GoRules())
	by := findingsByID(got)
	if len(by["GO_HARDCODED_AWS_KEY"]) != 1 {
		t.Errorf("GO_HARDCODED_AWS_KEY = %d; want 1", len(by["GO_HARDCODED_AWS_KEY"]))
	}
}

func TestJSRules_DetectInnerHTMLAssignment(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.js", `el.innerHTML = "<b>hi</b>";`)
	writeFile(t, dir, "bad.js", `el.innerHTML = userInput;`)
	writeFile(t, dir, "bad2.ts", `(el as HTMLElement).innerHTML = a + b;`)
	got, _ := Scan(dir, JSRules())
	by := findingsByID(got)
	if len(by["JS_INNER_HTML_USER_INPUT"]) != 2 {
		t.Errorf("JS_INNER_HTML_USER_INPUT = %d; want 2: %+v", len(by["JS_INNER_HTML_USER_INPUT"]), by["JS_INNER_HTML_USER_INPUT"])
	}
}

func TestJSRules_DetectEval(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.js", `eval("1+2");`)         // literal — safe
	writeFile(t, dir, "bad.js", `eval(userCode);`)     // identifier — flagged
	writeFile(t, dir, "bad2.js", `eval("a" + extra);`) // concat — flagged
	got, _ := Scan(dir, JSRules())
	by := findingsByID(got)
	if len(by["JS_EVAL_LITERAL"]) != 2 {
		t.Errorf("JS_EVAL_LITERAL = %d; want 2", len(by["JS_EVAL_LITERAL"]))
	}
}

func TestIaCRules_DetectPrivilegedContainer(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pod.yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    securityContext:
      privileged: true`)
	writeFile(t, dir, "ok.yaml", `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: x
    securityContext:
      privileged: false`)
	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	if len(by["IAC_K8S_PRIVILEGED_CONTAINER"]) != 1 {
		t.Errorf("IAC_K8S_PRIVILEGED_CONTAINER = %d; want 1", len(by["IAC_K8S_PRIVILEGED_CONTAINER"]))
	}
}

func TestIaCRules_DetectDockerfileLatestTag(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", `FROM python
RUN echo hi`)
	writeFile(t, dir, "Dockerfile.dev", `FROM python:3.11.7-slim
RUN echo hi`)
	got, _ := Scan(dir, IaCRules())
	by := findingsByID(got)
	// First file (no tag) should be flagged; second (pinned tag) should not.
	if len(by["IAC_DOCKER_LATEST_TAG"]) != 1 {
		t.Errorf("IAC_DOCKER_LATEST_TAG = %d; want 1: %+v", len(by["IAC_DOCKER_LATEST_TAG"]), by["IAC_DOCKER_LATEST_TAG"])
	}
}

func TestScan_SkipsNoiseDirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/x/pwned.js", `eval(userCode);`)
	writeFile(t, dir, "vendor/y/pwned.go", `var k = "AKIA1234567890ABCDEF"`)
	got, _ := Scan(dir, AllRules())
	if len(got) != 0 {
		t.Errorf("noise dirs should be skipped; got %d findings: %+v", len(got), got)
	}
}

func TestScan_ProducesEndpointAndLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.go", "package x\n\nvar K = \"AKIA1234567890ABCDEF\"\n")
	got, _ := Scan(dir, GoRules())
	if len(got) != 1 {
		t.Fatalf("got %d findings; want 1", len(got))
	}
	if !strings.HasSuffix(got[0].Endpoint, "app.go:3") {
		t.Errorf("endpoint = %q; want suffix app.go:3", got[0].Endpoint)
	}
	if got[0].Line == nil || *got[0].Line != got[0].Endpoint {
		t.Errorf("Line not mirrored to Endpoint: Line=%v Endpoint=%q", got[0].Line, got[0].Endpoint)
	}
}

func TestScan_EmptyRootIsHonestError(t *testing.T) {
	_, err := Scan("", AllRules())
	if err == nil {
		t.Errorf("expected error on empty rootDir")
	}
}

func TestScan_NonexistentRootIsError(t *testing.T) {
	_, err := Scan(filepath.Join(t.TempDir(), "no-such-dir"), AllRules())
	if err == nil {
		t.Errorf("expected error on nonexistent rootDir")
	}
}

func TestJavaRules_DetectsCoreVulns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Vuln.java", `public class Vuln {
  void run(String in) throws Exception {
    Runtime.getRuntime().exec("sh -c " + in);
    java.sql.Statement st = null;
    st.executeQuery("SELECT * FROM users WHERE id = " + in);
    java.security.MessageDigest.getInstance("MD5");
    new java.io.ObjectInputStream(System.in);
  }
}`)
	got, err := Scan(dir, JavaRules())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	by := findingsByID(got)
	for _, id := range []string{
		"JAVA_EXEC_COMMAND_INJECTION", "JAVA_SQL_INJECTION",
		"JAVA_WEAK_CRYPTO", "JAVA_INSECURE_DESERIALIZATION",
	} {
		if len(by[id]) != 1 {
			t.Errorf("%s = %d findings; want 1", id, len(by[id]))
		}
	}
}

func TestJavaRules_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	// Safe shapes that previously risked a false positive:
	//   - parameterized SQL (? placeholders, no concat)
	//   - literal exec argv
	//   - non-SQL Executor.execute(...) with a SQL-looking word ("update"/
	//     "delete from") AND a concat — incl. nested in an inner call. The
	//     MF-A regression: must NOT trip JAVA_SQL_INJECTION (Executor != JDBC).
	//   - SHA-256 (strong digest)
	writeFile(t, dir, "Safe.java", `public class Safe {
  void ok(java.sql.Connection c, String name, java.util.concurrent.Executor ex) throws Exception {
    var ps = c.prepareStatement("SELECT * FROM u WHERE id = ?");
    Runtime.getRuntime().exec(new String[]{"ls", "-la"});
    ex.execute(makeTask("update view for " + name));
    ex.execute("delete from cache " + name);
    java.security.MessageDigest.getInstance("SHA-256");
  }
}`)
	got, _ := Scan(dir, JavaRules())
	if len(got) != 0 {
		t.Errorf("expected no findings on safe Java, got %d: %+v", len(got), got)
	}
}

func TestJavaRules_v028_DetectsExpandedVulns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "More.java", `import javax.naming.directory.*;
public class More {
  void xxe() { javax.xml.parsers.DocumentBuilderFactory.newInstance(); }
  void cookie(jakarta.servlet.http.Cookie c) { c.setHttpOnly(false); }
  void rng() { String token = "t" + new java.util.Random().nextLong(); }
  void ldap(DirContext ctx, String u) throws Exception { ctx.search("ou=x", "(uid=" + u + ")", null); }
  void ssrf(jakarta.servlet.http.HttpServletRequest request) throws Exception { new java.net.URL(request.getParameter("u")); }
}`)
	by := findingsByID(mustScan(t, dir, JavaRules()))
	for _, id := range []string{"JAVA_XXE", "JAVA_INSECURE_COOKIE", "JAVA_WEAK_RANDOM", "JAVA_LDAP_INJECTION", "JAVA_SSRF"} {
		if len(by[id]) != 1 {
			t.Errorf("%s = %d findings; want 1", id, len(by[id]))
		}
	}
}

func TestJavaRules_v028_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	// Safe shapes the v0.28 rules must NOT flag:
	//   - new Random() with NO security co-token (dice roll)
	//   - setHttpOnly(true) / setSecure(true)
	//   - constant-URL request (no request-source token)
	//   - LDAP search with no string concat
	writeFile(t, dir, "Ok.java", `import javax.naming.directory.*;
public class Ok {
  void dice() { int n = new java.util.Random().nextInt(6); }
  void cookie(jakarta.servlet.http.Cookie c) { c.setHttpOnly(true); c.setSecure(true); }
  void okurl() throws Exception { new java.net.URL("https://api.example.com/health"); }
  void okldap(DirContext ctx) throws Exception { ctx.search("ou=x", "(uid=admin)", null); }
}`)
	if got := mustScan(t, dir, JavaRules()); len(got) != 0 {
		t.Errorf("expected no findings on safe Java, got %d: %+v", len(got), got)
	}
}

func mustScan(t *testing.T, dir string, rules []Rule) []evidence.Evidence {
	t.Helper()
	got, err := Scan(dir, rules)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return got
}
