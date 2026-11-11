import type { Worksheet } from 'exceljs'
import type { ClientData, Risk, Scan } from './clientData'
import { liveFindings } from './liveAdapters'

// Colores del libro (ARGB). Se mantienen sobrios para que el archivo se imprima bien.
const HEADER_FILL = 'FF12303F'
const HEADER_FONT = 'FFFFFFFF'
const SEVERITY_FILL: Record<string, string> = {
  critical: 'FFF8B4B4',
  high: 'FFFAD0B0',
  medium: 'FFFCEBB0',
  low: 'FFC9EBD2',
}
const SEVERITY_LABEL: Record<string, string> = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }
const DATE_FORMAT = 'dd/mm/yyyy hh:mm'

function riskFor(data: ClientData, scan: Scan | null): Risk | null {
  return scan ? data.risks.find((risk) => risk.escaneo_id === scan.id) ?? null : null
}

function toDate(value: string | null | undefined): Date | null {
  return value ? new Date(value) : null
}

function pad(value: number) {
  return String(value).padStart(2, '0')
}

/** Nombre del archivo: Reporte_<dominio>_<fecha>.xlsx (fecha local, AAAA-MM-DD). */
export function reportFileName(domain: string, now = new Date()): string {
  const safeDomain = domain.trim().toLowerCase().replace(/[^a-z0-9.-]+/g, '_') || 'organizacion'
  const date = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
  return `Reporte_${safeDomain}_${date}.xlsx`
}

function styleHeader(sheet: Worksheet, rowNumber: number) {
  const row = sheet.getRow(rowNumber)
  row.eachCell((cell) => {
    cell.font = { bold: true, color: { argb: HEADER_FONT } }
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: HEADER_FILL } }
    cell.alignment = { vertical: 'middle', wrapText: true }
  })
}

function addTable(sheet: Worksheet, headers: string[], rows: Array<Array<string | number | Date | null>>) {
  const header = sheet.addRow(headers)
  styleHeader(sheet, header.number)
  for (const values of rows) {
    const row = sheet.addRow(values)
    row.eachCell((cell) => {
      if (cell.value instanceof Date) cell.numFmt = DATE_FORMAT
      cell.alignment = { vertical: 'top', wrapText: true }
    })
  }
  return header.number
}

function addSectionTitle(sheet: Worksheet, title: string) {
  const row = sheet.addRow([title])
  row.font = { bold: true, size: 13, color: { argb: HEADER_FILL } }
  return row
}

function setWidths(sheet: Worksheet, widths: number[]) {
  widths.forEach((width, index) => { sheet.getColumn(index + 1).width = width })
}

function scanStatus(scan: Scan, risk: Risk | null): string {
  if (scan.estado === 'fallido') return 'fallido'
  return scan.estado === 'completado' && risk && !risk.es_parcial ? 'completado' : 'incompleto'
}

/**
 * Genera y descarga un Excel con la información del resumen (overview).
 * Usa los mismos datos que la pantalla (ClientData), así las cifras coinciden.
 */
export async function exportOverviewToExcel(data: ClientData, latest: Scan | null): Promise<void> {
  // Se carga bajo demanda para no aumentar el tamaño inicial de la aplicación.
  // exceljs es CommonJS: según el empaquetador, la clase llega en `default` o en el módulo mismo.
  const excelModule = await import('exceljs')
  const { Workbook } = (excelModule as unknown as { default?: typeof excelModule }).default ?? excelModule
  const now = new Date()
  const risk = riskFor(data, latest)
  const findings = liveFindings(data)
  const sourceResults = new Map(data.sourceResults.map((result) => [result.fuente_id, result]))
  const consulted = data.sourceResults.filter((result) => result.estado === 'completado').length
  const coverage = data.sources.length ? Math.round(consulted / data.sources.length * 100) : 0

  const workbook = new Workbook()
  workbook.creator = 'BaxterSec'
  workbook.created = now

  // ───────── 1. Resumen ─────────
  const summary = workbook.addWorksheet('Resumen')
  setWidths(summary, [38, 30, 22, 22])
  const title = summary.addRow([`Reporte de exposición · ${data.organization.nombre}`])
  title.font = { bold: true, size: 16, color: { argb: HEADER_FILL } }
  summary.addRow(['Dominio principal', data.organization.dominio_principal])
  summary.addRow(['Fecha del reporte', now]).getCell(2).numFmt = DATE_FORMAT
  summary.addRow(['Último análisis terminado', toDate(latest?.finalizado_en) ?? 'Todavía no hay un análisis terminado']).getCell(2).numFmt = DATE_FORMAT
  summary.addRow(['Estado del último análisis', latest?.estado ?? 'Pendiente'])
  summary.getColumn(2).alignment = { horizontal: 'left' }
  summary.addRow([])

  addSectionTitle(summary, 'Risk score del último análisis (0–100)')
  if (risk) {
    addTable(summary, ['Categoría', 'Puntaje'], [
      ['Global', risk.puntaje_global],
      ['Infraestructura', risk.infraestructura],
      ['Identidad digital', risk.identidad_digital],
      ['Configuración', risk.configuracion],
      ['Fuga de datos', risk.fuga_de_datos],
    ])
    summary.addRow(['Resultado', risk.es_parcial ? 'Parcial' : 'Actual'])
    if (risk.es_parcial && risk.fuentes_faltantes.length) summary.addRow(['Fuentes faltantes', risk.fuentes_faltantes.join(', ')])
  } else {
    summary.addRow(['El puntaje aparecerá al terminar un análisis.'])
  }
  summary.addRow([])

  addSectionTitle(summary, 'Resumen de la organización')
  const criticalCount = findings.filter((finding) => finding.severity === 'critical').length
  addTable(summary, ['Indicador', 'Valor'], [
    ['Activos históricos', data.assetCount],
    ['Hallazgos históricos', data.findingCount],
    ['Críticos históricos', criticalCount],
    ['Análisis', data.scanCount],
    ['Hallazgos abiertos históricos', data.findings.filter((item) => item.estado === 'abierto').length],
    ['Observaciones del último análisis', data.observations.length],
    ['Fuentes completadas', consulted],
    ['Cobertura de fuentes (%)', coverage],
  ])
  const notes: string[] = []
  if (data.assetCount > data.assets.length) notes.push(`Activos: se listan ${data.assets.length} de ${data.assetCount}.`)
  if (data.findingCount > data.findings.length) notes.push(`Hallazgos: se listan ${data.findings.length} de ${data.findingCount}.`)
  if (data.scanCount > data.scans.length) notes.push(`Análisis: se listan ${data.scans.length} de ${data.scanCount}.`)
  if (notes.length) {
    summary.addRow([])
    summary.addRow(['Nota: el dashboard carga un máximo de registros por consulta. ' + notes.join(' ')]).font = { italic: true }
  }

  // ───────── 2. Evolución del riesgo ─────────
  const evolution = workbook.addWorksheet('Evolución del riesgo')
  setWidths(evolution, [20, 14, 16, 16, 18, 16, 16])
  const scansWithRisk = data.scans
    .filter((scan) => scan.finalizado_en && riskFor(data, scan))
    .sort((a, b) => new Date(a.finalizado_en!).getTime() - new Date(b.finalizado_en!).getTime())
  const evolutionHeader = addTable(evolution, ['Fecha de finalización', 'Estado', 'Puntaje global', 'Infraestructura', 'Identidad digital', 'Configuración', 'Fuga de datos'],
    scansWithRisk.map((scan) => {
      const r = riskFor(data, scan)!
      return [toDate(scan.finalizado_en), scanStatus(scan, r), r.puntaje_global, r.infraestructura, r.identidad_digital, r.configuracion, r.fuga_de_datos]
    }))
  evolution.views = [{ state: 'frozen', ySplit: evolutionHeader }]
  if (!scansWithRisk.length) evolution.addRow(['Todavía no hay análisis con puntaje.'])

  // ───────── 3. Hallazgos ─────────
  const findingsSheet = workbook.addWorksheet('Hallazgos')
  setWidths(findingsSheet, [14, 38, 34, 12, 12, 24, 24])
  addSectionTitle(findingsSheet, 'Hallazgos por severidad')
  addTable(findingsSheet, ['Severidad', 'Cantidad'], (['critical', 'high', 'medium', 'low'] as const).map((key) => [
    SEVERITY_LABEL[key],
    findings.filter((finding) => finding.severity === key).length,
  ]))
  findingsSheet.addRow([])
  addSectionTitle(findingsSheet, 'Detalle de hallazgos (ordenados por severidad)')
  const findingsHeader = addTable(findingsSheet, ['Severidad', 'Hallazgo', 'Activo', 'Confianza (%)', 'Estado', 'Regla', 'Fuente'],
    findings.map((finding) => [SEVERITY_LABEL[finding.severity], finding.title, finding.asset, finding.confidence, finding.status, finding.rule, finding.sources.join(', ')]))
  findings.forEach((finding, index) => {
    findingsSheet.getRow(findingsHeader + 1 + index).getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_FILL[finding.severity] } }
  })
  if (!findings.length) findingsSheet.addRow(['No hay hallazgos registrados.'])

  // ───────── 4. Activos ─────────
  const assetsSheet = workbook.addWorksheet('Activos')
  setWidths(assetsSheet, [18, 46, 22, 22])
  addSectionTitle(assetsSheet, 'Inventario por tipo')
  const types = [...new Set(data.assets.map((asset) => asset.tipo))]
  addTable(assetsSheet, ['Tipo', 'Cantidad'], types.map((type) => [type, data.assets.filter((asset) => asset.tipo === type).length]))
  assetsSheet.addRow([])
  addSectionTitle(assetsSheet, 'Listado de activos')
  addTable(assetsSheet, ['Tipo', 'Valor', 'Visto por primera vez', 'Visto por última vez'],
    data.assets.map((asset) => [asset.tipo, asset.valor, toDate(asset.visto_primera_vez), toDate(asset.visto_ultima_vez)]))
  if (!data.assets.length) assetsSheet.addRow(['Aún no hay activos descubiertos.'])

  // ───────── 5. Fuentes ─────────
  const sourcesSheet = workbook.addWorksheet('Fuentes')
  setWidths(sourcesSheet, [24, 18, 16, 16, 14, 14, 44])
  addTable(sourcesSheet, ['Fuente', 'Tipo de acceso', 'Estado (último análisis)', 'Observaciones generadas', 'Nuevas', 'Duplicadas', 'Error'],
    data.sources.map((source) => {
      const result = sourceResults.get(source.id)
      return [source.nombre, source.tipo_acceso, result?.estado ?? 'Sin ejecutar', result?.observaciones_generadas ?? null, result?.observaciones_nuevas ?? null, result?.observaciones_duplicadas ?? null, result?.error ?? null]
    }))
  sourcesSheet.addRow([])
  sourcesSheet.addRow(['Cobertura del análisis (%)', coverage]).font = { bold: true }

  // ───────── 6. Actividad reciente ─────────
  const activity = workbook.addWorksheet('Actividad reciente')
  setWidths(activity, [22, 22, 16, 16])
  addTable(activity, ['Inicio', 'Fin', 'Estado', 'Puntaje de riesgo'],
    data.scans.map((scan) => [toDate(scan.iniciado_en), toDate(scan.finalizado_en), scan.estado, riskFor(data, scan)?.puntaje_global ?? null]))
  if (!data.scans.length) activity.addRow(['Todavía no hay análisis registrados.'])

  // ───────── Descarga ─────────
  const buffer = await workbook.xlsx.writeBuffer()
  const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = reportFileName(data.organization.dominio_principal, now)
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}