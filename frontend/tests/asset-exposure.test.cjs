const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')

const source = fs.readFileSync(path.join(__dirname, '../src/pages/dashboard/services/liveAdapters.ts'), 'utf8')
const code = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText
const exportsObject = {}
const localRequire = (name) => name === './sourcePolicy'
  ? { isActiveSource: () => true }
  : require(name)
vm.runInNewContext(code, { exports: exportsObject, require: localRequire })

function data(exposicion, estadoCobertura, findingState = null, asset = {}, motivo = null) {
  const finding = findingState ? {
    id: 'finding', escaneo_id: 'scan', categoria: 'infraestructura', severidad: 'alta',
    confianza: 0.9, estado: findingState, activo_id: 'asset', fuente_id: 'source',
    regla_id: 'rule', evidencia: {},
  } : null
  return {
    organization: { id: 'org', nombre: 'Control', dominio_principal: 'example.com' },
    assets: [{ id: 'asset', tipo: 'subdominio', valor: 'api.example.com', visto_primera_vez: '2026-11-01T00:00:00Z', visto_ultima_vez: '2026-11-19T00:00:00Z', ...asset }],
    sources: [{ id: 'source', nombre: 'SpiderFoot' }],
    rules: [{ id: 'rule', peso: 10, esta_activa: true }],
    observations: [{ id: 'obs', activo_id: 'asset', fuente_id: 'source', datos: { evaluacion: 'completa' } }],
    assetObservations: [], findings: finding ? [finding] : [],
    latestFinishedScan: { id: 'scan', iniciado_en: '2026-11-19T00:00:00Z' },
    risks: [{ escaneo_id: 'scan', cobertura: { infraestructura: { activos: [
      { id: 'asset', exposicion, estado_cobertura: estadoCobertura, motivo },
    ] } } }],
  }
}

test('assets consume backend exposure and keep coverage separate', () => {
  const evaluated = exportsObject.liveAssets(data('Evaluado sin hallazgos', 'evaluado'))[0]
  assert.equal(evaluated.exposure, 'Evaluado sin hallazgos')
  assert.equal(evaluated.coverageState, 'Evaluación aplicable completada')

  const partial = exportsObject.liveAssets(data('Alta', 'parcial', 'abierto'))[0]
  assert.equal(partial.exposure, 'Alta')
  assert.equal(partial.coverageState, 'Cobertura parcial')

  const unresolvedMarker = exportsObject.liveAssets(data('Sin evaluar', 'sin_evaluacion'))[0]
  assert.equal(unresolvedMarker.exposure, 'Sin evaluar')
})

test('legacy Sin evaluar is refined without requiring a new scan', () => {
  const sharedIp = exportsObject.liveAssets(data(
    'Sin evaluar', 'sin_evaluacion', null,
    { tipo: 'ip', valor: '64.29.17.67' },
    'Fuera del alcance autorizado; una relación DNS no autoriza la IP del proveedor',
  ))[0]
  assert.equal(sharedIp.exposure, 'Fuera de alcance')

  const email = exportsObject.liveAssets(data(
    'Sin evaluar', 'sin_evaluacion', null,
    { tipo: 'correo', valor: 'contact@example.com' },
    'Tipo sin consulta compatible en las fuentes configuradas',
  ))[0]
  assert.equal(email.exposure, 'Sin evaluación compatible')

  const fixture = exportsObject.liveAssets(data(
    'Sin evaluar', 'sin_evaluacion', null,
    { tipo: 'servicio', valor: '203.0.113.10:22/tcp' },
  ))[0]
  assert.equal(fixture.exposure, 'Histórico/sintético')
})
