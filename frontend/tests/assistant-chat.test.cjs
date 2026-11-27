const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')

const source = fs.readFileSync(path.join(__dirname, '../src/pages/dashboard/services/assistantChat.ts'), 'utf8')
const code = ts.transpileModule(source.replaceAll('import.meta.env', '__env'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText

function loadService(session, fetchImpl) {
  const exportsObject = {}
  vm.runInNewContext(code, {
    exports: exportsObject,
    require: () => ({ supabase: { auth: { getSession: async () => ({ data: { session } }) } } }),
    fetch: fetchImpl,
    __env: { VITE_API_URL: 'http://localhost:8000/' },
  })
  return exportsObject
}

test('chat sends the authenticated scan conversation to the backend', async () => {
  let request
  const service = loadService({ access_token: 'session-token' }, async (url, options) => {
    request = { url, options }
    return { ok: true, json: async () => ({ respuesta: 'Riesgo parcial.', escaneo_id: 'scan-1', dominio: 'ejemplo.com' }) }
  })
  const answer = await service.sendAssistantMessage([{ role: 'user', content: '¿Qué significa el riesgo?' }], 'scan-1')
  assert.equal(request.url, 'http://localhost:8000/api/asistente/chat')
  assert.equal(request.options.headers.Authorization, 'Bearer session-token')
  assert.deepEqual(JSON.parse(request.options.body), {
    mensajes: [{ role: 'user', content: '¿Qué significa el riesgo?' }],
    escaneo_id: 'scan-1',
  })
  assert.equal(answer.respuesta, 'Riesgo parcial.')
})

test('chat exposes a missing backend configuration without sending a browser API key', async () => {
  const service = loadService({ access_token: 'session-token' }, async () => ({
    ok: false, json: async () => ({ detail: 'El asistente de IA no está configurado' }),
  }))
  await assert.rejects(service.sendAssistantMessage([{ role: 'user', content: 'Hola' }], null), /no está configurado/)
})
