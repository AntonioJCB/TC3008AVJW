const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')
const React = require('react')
const { renderToStaticMarkup } = require('react-dom/server')

const source = fs.readFileSync(path.join(__dirname, '../src/pages/dashboard/components/NvdPotentialEvidence.tsx'), 'utf8')
const code = ts.transpileModule(source, {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText
const helperSource = fs.readFileSync(path.join(__dirname, '../src/pages/dashboard/components/nvdPotential.ts'), 'utf8')
const helperCode = ts.transpileModule(helperSource, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText
const helperExports = {}
vm.runInNewContext(helperCode, { exports: helperExports })
const exportsObject = {}
vm.runInNewContext(code, { exports: exportsObject, require: name => name === './nvdPotential' ? helperExports : require(name) })
const Component = exportsObject.default

function observation(id, cve, verified = false) {
  return {
    id, activo_id: 'asset-1', fuente_id: 'spiderfoot', atributo: 'cve', observado_en: '2026-11-18T16:40:20.371Z',
    datos: {
      cve, verificado: verified, fuente_enriquecimiento: 'NVD',
      coincidencia: 'potencial_producto_version',
      productos_versiones: [{ producto: 'Apache HTTP Server', version: '2.4.7', cpe: 'cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*' }],
      nvd: { publicado_en: '2021-10-05T09:15:00.000', modificado_en: '2025-11-20T12:00:00.000',
        cvss: { severidad: 'HIGH', puntaje_base: 7.5 }, referencia: `https://nvd.nist.gov/vuln/detail/${cve}` },
      evidencias_osint: [{ proveedor: 'urlscan', valor: 'Apache/2.4.7 (Ubuntu)', referencias: ['control-urlscan'] }],
    },
  }
}

test('NVD report groups potential CVEs and preserves technical evidence without claiming risk', () => {
  const first = observation('o1', 'CVE-2021-41773')
  first.datos.explotacion = {
    kev: { presente: true, fecha_incorporacion: '2021-11-03' },
    epss: { probabilidad: 0.975, percentil: 0.998, fecha_actualizacion: '2026-11-19' },
    prioridad_operativa: 'prioritaria', modifica_risk_score: false,
  }
  const html = renderToStaticMarkup(React.createElement(Component, {
    observations: [first, observation('o2', 'CVE-2021-42013')],
  }))
  assert.match(html, /NVD: 2 vulnerabilidades potenciales, 0 verificadas/)
  assert.match(html, /Apache HTTP Server 2.4.7/)
  assert.match(html, /cpe:2.3:a:apache:http_server:2.4.7/)
  assert.match(html, /CVSS informativo: HIGH/)
  assert.match(html, /Evidencias OSINT originales conservadas: 1 de urlscan/)
  assert.match(html, /no aumentan el Risk Score/)
  assert.match(html, /1 presentes en CISA KEV/)
  assert.match(html, /EPSS máximo 97.5%/)
  assert.match(html, /CISA KEV desde 2021-11-03/)
  assert.match(html, /percentil 99.8%/)
  assert.match(html, /CVE-2021-41773/)
  assert.match(html, /https:\/\/nvd.nist.gov\/vuln\/detail\/CVE-2021-42013/)
})

test('OSV package evidence is shown without being promoted to a verified vulnerability', () => {
  const item = observation('o3', 'CVE-2019-10906')
  item.datos.fuente_enriquecimiento = 'OSV'
  item.datos.fuentes_enriquecimiento = ['OSV']
  delete item.datos.productos_versiones
  delete item.datos.nvd
  item.datos.paquetes_versiones = [{ paquete: 'jinja2', ecosistema: 'PyPI', version: '2.4.1' }]
  item.datos.osv = [{ id: 'GHSA-462W-V97R-4M45', publicado_en: '2019-04-07T00:00:00Z',
    modificado_en: '2024-11-18T00:00:00Z', severidad: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] }]
  item.datos.referencias_enriquecimiento = ['https://osv.dev/vulnerability/GHSA-462W-V97R-4M45']
  const html = renderToStaticMarkup(React.createElement(Component, { observations: [item] }))
  assert.match(html, /OSV: 1 vulnerabilidades potenciales, 0 verificadas/)
  assert.match(html, /PyPI \/ jinja2 \/ 2.4.1/)
  assert.match(html, /CVSS informativo: CVSS_V3/)
  assert.match(html, /no aumentan el Risk Score/)
})

test('verified or non-NVD CVEs are not presented as NVD potential matches', () => {
  assert.equal(renderToStaticMarkup(React.createElement(Component, {
    observations: [observation('o1', 'CVE-2021-41773', true)],
  })), '')
})
