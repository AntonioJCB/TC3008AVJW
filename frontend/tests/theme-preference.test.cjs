const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const ts = require('typescript')

const source = fs.readFileSync(path.join(__dirname, '../src/services/themePreference.ts'), 'utf8')
const code = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText
const preference = {}
vm.runInNewContext(code, { exports: preference })

test('theme is stored on the authenticated account and restored independently', async () => {
  const users = new Map([
    ['alice', { id: 'alice', user_metadata: {} }],
    ['bob', { id: 'bob', user_metadata: { portal_theme: 'light' } }],
  ])
  const authFor = (id) => ({
    updateUser: async ({ data }) => {
      const user = users.get(id)
      user.user_metadata = { ...user.user_metadata, ...data }
      return { data: { user }, error: null }
    },
  })

  assert.equal(preference.getThemePreference(users.get('alice').user_metadata), 'dark')
  assert.equal(preference.getThemePreference(users.get('bob').user_metadata), 'light')
  await preference.saveThemePreference(authFor('alice'), 'alice', 'light')
  await preference.saveThemePreference(authFor('bob'), 'bob', 'dark')

  assert.equal(preference.getThemePreference(users.get('alice').user_metadata), 'light')
  assert.equal(preference.getThemePreference(users.get('bob').user_metadata), 'dark')
  assert.equal(preference.getThemePreference({ portal_theme: 'invalid' }), 'dark')
})

test('theme save rejects a response for another account', async () => {
  const wrongAccount = { updateUser: async () => ({ data: { user: { id: 'bob', user_metadata: { portal_theme: 'light' } } }, error: null }) }
  await assert.rejects(preference.saveThemePreference(wrongAccount, 'alice', 'light'), /No se pudo guardar/)
})
