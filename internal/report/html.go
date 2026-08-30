package report

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

// WriteHTML writes report.html into dir: one self-contained file, inline CSS,
// no scripts, no external assets. It has to survive being emailed to an
// auditor who will open it offline.
func WriteHTML(r *Report, dir string) (string, error) {
	path := filepath.Join(dir, "report.html")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return path, htmlTmpl.Execute(f, r)
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"base":    filepath.Base,
	"upper":   strings.ToUpper,
	"join":    func(xs []string) string { return strings.Join(xs, ", ") },
	"none":    countOrNone,
	"gloss":   func(v string) string { return verdictGloss[v] },
	"vclass":  func(v string) string { return strings.ToLower(strings.ReplaceAll(v, "_", "-")) },
	"stamp":   func(r *Report) string { return r.ScannedAt.Format("2006-01-02 15:04 MST") },
	"hasRule": func(m map[string]int, k string) bool { return m[k] > 0 },
}).Parse(htmlSrc))

const htmlSrc = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>gatescan — {{.Subject}}</title>
<style>
:root{
  --ground:#f4f6f8; --surface:#fff; --surface2:#edf0f4; --ink:#141920; --ink2:#3d4753;
  --muted:#69747f; --hair:#dce1e7; --hairs:#c3ccd4; --accent:#1d4e8f;
  --pine:#2e6b4f; --pines:#e1ede6; --ochre:#8a6216; --ochres:#f3ebd8;
  --oxide:#9b3226; --oxides:#f6e3df;
}
@media (prefers-color-scheme:dark){:root{
  --ground:#0f1216; --surface:#161a20; --surface2:#1d222a; --ink:#e7eaee; --ink2:#c2c9d2;
  --muted:#8e99a6; --hair:#262c35; --hairs:#333b46; --accent:#77a6de;
  --pine:#6bae87; --pines:#16241c; --ochre:#cfa34f; --ochres:#26200f;
  --oxide:#d87764; --oxides:#2a1714;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);line-height:1.6;
 font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:15px}
.wrap{max-width:960px;margin:0 auto;padding:40px 22px 80px}
h1{font-size:30px;margin:0 0 10px;letter-spacing:-.015em}
h2{font-size:19px;margin:38px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--ink)}
.mono,code,.q{font-family:ui-monospace,SFMono-Regular,Menlo,"Cascadia Mono",monospace}
.q{font-size:14px;color:var(--ink2);background:var(--surface2);border-left:3px solid var(--accent);
 padding:11px 14px;border-radius:2px;margin:0 0 22px}
.meta{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--muted);
 display:flex;flex-wrap:wrap;gap:5px 18px;margin-bottom:26px}
.figs{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;
 background:var(--hair);border:1px solid var(--hair);border-radius:3px;overflow:hidden;margin-bottom:8px}
.fig{background:var(--surface);padding:14px 16px}
.fig .n{font-family:ui-monospace,monospace;font-size:23px;display:block;font-variant-numeric:tabular-nums}
.fig .l{font-size:12px;color:var(--muted)}
.job{background:var(--surface);border:1px solid var(--hair);border-radius:3px;padding:15px 18px;margin-bottom:12px}
.jhead{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:baseline;margin-bottom:4px}
.jhead .id{font-family:ui-monospace,monospace;font-weight:600}
.v{font-family:ui-monospace,monospace;font-size:10.5px;letter-spacing:.09em;padding:3px 8px;border-radius:2px}
.v.establishes{background:var(--pines);color:var(--pine)}
.v.partial{background:var(--ochres);color:var(--ochre)}
.v.establishes-nothing{background:var(--oxides);color:var(--oxide)}
.v.no-assertions{background:var(--surface2);color:var(--muted)}
.gloss{color:var(--muted);font-size:13.5px}
.assert{border-top:1px dotted var(--hairs);margin-top:11px;padding-top:10px;font-size:13.5px}
.assert .s{font-weight:600}
.assert dl{display:grid;grid-template-columns:auto 1fr;gap:2px 12px;margin:5px 0 0}
.assert dt{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--muted);letter-spacing:.05em}
.assert dd{margin:0;font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.f{background:var(--surface);border:1px solid var(--hair);border-left:3px solid var(--hairs);
 border-radius:3px;padding:14px 18px;margin-bottom:11px}
.f.critical{border-left-color:var(--oxide)} .f.high{border-left-color:var(--ochre)}
.f.medium{border-left-color:var(--accent)}
.fh{display:flex;flex-wrap:wrap;gap:7px 11px;align-items:baseline;margin-bottom:7px}
.rule{font-family:ui-monospace,monospace;font-weight:600;font-size:14.5px}
.sev{font-family:ui-monospace,monospace;font-size:10.5px;letter-spacing:.09em;padding:3px 8px;border-radius:2px}
.sev.critical{background:var(--oxides);color:var(--oxide)}
.sev.high{background:var(--ochres);color:var(--ochre)}
.sev.medium{background:var(--surface2);color:var(--accent)}
.f dl{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;margin:0}
.f dt{font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}
.f dd{margin:0;color:var(--ink2)}
.at{font-family:ui-monospace,monospace;font-size:12.5px}
.skip{color:var(--muted);font-size:13px;font-family:ui-monospace,monospace;margin:10px 0}
.clean{background:var(--pines);color:var(--pine);border-radius:3px;padding:13px 16px;font-size:14px}
footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--hair);color:var(--muted);
 font-family:ui-monospace,monospace;font-size:12px}
</style></head><body><div class="wrap">

<h1>gatescan report</h1>
<div class="meta">
  <span>{{.Version}}</span><span>subject: {{.Subject}}</span><span>{{stamp .}}</span>
</div>
<p class="q">{{.Question}}</p>

<div class="figs">
  <div class="fig"><span class="n">{{.Summary.Workflows}}</span><span class="l">workflow(s)</span></div>
  <div class="fig"><span class="n">{{.Summary.Jobs}}</span><span class="l">job(s)</span></div>
  <div class="fig"><span class="n">{{.Summary.Findings}}</span><span class="l">finding(s)</span></div>
  <div class="fig"><span class="n">{{.Summary.JobsEstablishNothing}}</span><span class="l">job(s) establishing nothing</span></div>
</div>

{{range .Workflows}}
<h2>{{if .Name}}{{.Name}}{{else}}{{base .Path}}{{end}}</h2>
<div class="meta"><span>{{.Path}}</span></div>

{{range .Jobs}}
<div class="job">
  <div class="jhead">
    <span class="id">{{.ID}}</span>
    <span class="v {{vclass .Verdict}}">{{.Verdict}}</span>
    <span class="gloss">{{gloss .Verdict}}</span>
  </div>
  {{range .Assertions}}
  <div class="assert">
    <div class="s">check: {{.Step}}</div>
    <dl>
      <dt>EXTERNAL</dt><dd>{{none .External}}</dd>
      <dt>INTERNAL</dt><dd>{{none .Internal}}</dd>
    </dl>
  </div>
  {{end}}
</div>
{{end}}

{{if .Findings}}
{{range .Findings}}
<div class="f {{.Severity}}">
  <div class="fh">
    <span class="rule">{{.Rule}}</span>
    <span class="sev {{.Severity}}">{{upper .Severity}}</span>
  </div>
  <dl>
    {{if .Step}}<dt>Step</dt><dd>{{.Step}}</dd>{{end}}
    <dt>At</dt><dd class="at">{{$.Subject}} line {{.Line}}</dd>
    <dt>What</dt><dd>{{.Detail}}</dd>
    <dt>Referent</dt><dd>{{.Referent}}</dd>
  </dl>
</div>
{{end}}
{{else}}
<div class="clean">No findings. Every check in this workflow has at least one input it did not produce.</div>
{{end}}

{{range .Skipped}}<p class="skip">skipped — {{.}}</p>{{end}}
{{end}}

<footer>gatescan {{.Version}} · offline static analysis · no network access, no service dependency</footer>
</div></body></html>
`
