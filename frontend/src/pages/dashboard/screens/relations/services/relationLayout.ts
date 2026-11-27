import type { RelationEdge, RelationNode } from './relationsMock'

type Size = { width: number; height: number }
type Point = { x: number; y: number }
type Box = { id: string; left: number; right: number; top: number; bottom: number }

const nodeWidth = 184
const nodeHeight = 142
const gap = 230
const byName = (left: RelationNode, right: RelationNode) => left.name.localeCompare(right.name) || left.id.localeCompare(right.id)
const historical = (node: RelationNode) => node.kind.includes('Histórico / sintético')

function serviceAddress(value: string) {
  const bracketed = /^\[([^\]]+)\]:/.exec(value)
  const separator = value.indexOf(':')
  return bracketed ? bracketed[1] : separator < 0 ? value : value.slice(0, separator)
}

export function layoutRelationNodes(nodes: RelationNode[], edges: RelationEdge[]): Size {
  const root = nodes.find((node) => node.id === 'root')
  const live = nodes.filter((node) => node.id !== 'root' && !historical(node))
  const names = live.filter((node) => node.badge === 'SUB').sort(byName)
  const identities = live.filter((node) => node.badge === 'ID').sort(byName)
  const ips = live.filter((node) => node.badge === 'IP')
  const services = live.filter((node) => node.badge === 'SV').sort(byName)
  const other = live.filter((node) => !['SUB', 'ID', 'IP', 'SV'].includes(node.badge)).sort(byName)
  const archived = nodes.filter((node) => node.id !== 'root' && historical(node))
  const ipNeighbors = new Map<string, Set<string>>()
  for (const edge of edges) {
    const ip = ips.find((node) => node.id === edge.from || node.id === edge.to)
    if (!ip) continue
    const neighbor = edge.from === ip.id ? edge.to : edge.from
    if (!ipNeighbors.has(neighbor)) ipNeighbors.set(neighbor, new Set())
    ipNeighbors.get(neighbor)!.add(ip.id)
  }

  // Keep names sharing DNS addresses adjacent; ties use stable names and IDs.
  const orderedNames: RelationNode[] = []
  while (names.length) {
    const previous = orderedNames.at(-1)
    names.sort((left, right) => {
      const shared = (node: RelationNode) => previous
        ? [...(ipNeighbors.get(previous.id) ?? [])].filter((id) => ipNeighbors.get(node.id)?.has(id)).length : 0
      return shared(right) - shared(left) || byName(left, right)
    })
    orderedNames.push(names.shift()!)
  }
  const nameRank = new Map(orderedNames.map((node, index) => [node.id, index]))
  nameRank.set('root', (orderedNames.length - 1) / 2)
  ips.sort((left, right) => {
    const rank = (node: RelationNode) => {
      const linked = edges.filter((edge) => edge.from === node.id || edge.to === node.id)
        .map((edge) => nameRank.get(edge.from === node.id ? edge.to : edge.from))
        .filter((value): value is number => value !== undefined)
      return linked.length ? linked.reduce((sum, value) => sum + value, 0) / linked.length : orderedNames.length / 2
    }
    return rank(left) - rank(right) || byName(left, right)
  })

  const ipColumns = Math.ceil(ips.length / 2)
  const ipRows = Math.min(2, ips.length)
  const width = Math.max(1160, 360 + Math.max(0, ipColumns - 1) * gap,
    420 + orderedNames.length * 280, 400 + (services.length + other.length) * 210,
    800 + Math.max(0, Math.ceil(identities.length / 2) - 1) * 440,
    400 + archived.length * 210)
  const center = width / 2
  const positions = new Map<string, Point>()
  if (root) positions.set(root.id, { x: center, y: 165 })
  orderedNames.forEach((node, index) => {
    const slot = index - (orderedNames.length - 1) / 2
    positions.set(node.id, { x: center + slot * 280, y: 405 })
  })
  identities.forEach((node, index) => {
    const side = index % 2 === 0 ? -1 : 1
    positions.set(node.id, { x: center + side * (300 + Math.floor(index / 2) * 220), y: 160 })
  })
  ips.forEach((node, index) => positions.set(node.id, {
    x: center + (Math.floor(index / 2) - (ipColumns - 1) / 2) * gap,
    y: (orderedNames.length ? 635 : 480) + index % 2 * 195,
  }))
  const usedServiceX: number[] = []
  for (const node of [...services, ...other]) {
    const related = ips.find((ip) => ip.name === serviceAddress(node.name))
    const ideal = related ? positions.get(related.id)!.x : center
    const candidates = [0, 1, -1, 2, -2, 3, -3, 4, -4].map((shift) => ideal + shift * gap)
    const x = candidates.find((candidate) => candidate >= 120 && candidate <= width - 120
      && usedServiceX.every((occupied) => Math.abs(candidate - occupied) >= 210)) ?? center + usedServiceX.length * gap
    usedServiceX.push(x)
    positions.set(node.id, { x, y: ips.length ? (ipRows === 2 ? 1060 : 875) : 705 })
  }
  const historicalY = archived.length ? (services.length || other.length ? (ipRows === 2 ? 1320 : 1115)
    : ips.length ? (ipRows === 2 ? 1100 : 875) : 705) : 0
  const archivedIp = archived.filter((node) => node.badge === 'IP').sort(byName)
  const archivedOther = archived.filter((node) => node.badge !== 'IP').sort(byName)
  const archivedOrder = [...archivedIp, ...archivedOther]
  archivedOrder.forEach((node, index) => {
    const slot = index === 0 ? 0 : (index % 2 ? -1 : 1) * Math.ceil(index / 2)
    positions.set(node.id, { x: center + slot * gap, y: historicalY })
  })
  const height = historicalY ? historicalY + 185 : services.length || other.length ? (ipRows === 2 ? 1245 : 1060)
    : ips.length ? (ipRows === 2 ? 1015 : 820) : orderedNames.length ? 610 : 450
  for (const node of nodes) {
    const point = positions.get(node.id) ?? { x: center, y: height / 2 }
    node.x = point.x / width * 100
    node.y = point.y / height * 100
  }
  return { width, height }
}

function crossesBox(start: Point, end: Point, box: Box) {
  // Liang–Barsky clipping against a padded node rectangle.
  const dx = end.x - start.x
  const dy = end.y - start.y
  const tests = [[-dx, start.x - box.left], [dx, box.right - start.x],
    [-dy, start.y - box.top], [dy, box.bottom - start.y]]
  let near = 0
  let far = 1
  for (const [p, q] of tests) {
    if (p === 0) { if (q < 0) return false; continue }
    const ratio = q / p
    if (p < 0) near = Math.max(near, ratio)
    else far = Math.min(far, ratio)
    if (near > far) return false
  }
  return true
}

function segments(points: Point[]) {
  return points.slice(1).map((point, index) => [points[index], point] as const)
}

function crossesEdge(a: Point, b: Point, c: Point, d: Point) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const ex = d.x - c.x
  const ey = d.y - c.y
  const denominator = dx * ey - dy * ex
  if (Math.abs(denominator) < .001) return false
  const t = ((c.x - a.x) * ey - (c.y - a.y) * ex) / denominator
  const u = ((c.x - a.x) * dy - (c.y - a.y) * dx) / denominator
  return t > .001 && t < .999 && u > .001 && u < .999
}

export function routeRelationEdges(nodes: RelationNode[], edges: RelationEdge[], size: Size): Map<string, string> {
  const points = new Map(nodes.map((node) => [node.id, { x: node.x * size.width / 100, y: node.y * size.height / 100 }]))
  const boxes: Box[] = nodes.map((node) => {
    const point = points.get(node.id)!
    const halfWidth = (node.id === 'root' ? 210 : nodeWidth) / 2 + 13
    return { id: node.id, left: point.x - halfWidth, right: point.x + halfWidth,
      top: point.y - nodeHeight / 2 - 13, bottom: point.y + nodeHeight / 2 + 13 }
  })
  const routed = new Map<string, string>()
  const previousSegments: ReturnType<typeof segments> = []
  for (const edge of [...edges].sort((left, right) => left.id.localeCompare(right.id))) {
    const start = points.get(edge.from)
    const end = points.get(edge.to)
    if (!start || !end) continue
    const blockers = boxes.filter((box) => box.id !== edge.from && box.id !== edge.to)
    const xLanes = [25, size.width - 25, (start.x + end.x) / 2,
      ...blockers.flatMap((box) => [box.left - 20, box.right + 20])]
    const yLanes = [25, size.height - 25, (start.y + end.y) / 2,
      ...blockers.flatMap((box) => [box.top - 20, box.bottom + 20])]
    const candidates: Point[][] = [[start, end],
      [start, { x: end.x, y: start.y }, end], [start, { x: start.x, y: end.y }, end],
      ...xLanes.filter((x) => x > 0 && x < size.width).map((x) => [start, { x, y: start.y }, { x, y: end.y }, end]),
      ...yLanes.filter((y) => y > 0 && y < size.height).map((y) => [start, { x: start.x, y }, { x: end.x, y }, end])]
    const score = (candidate: Point[]) => {
      const lines = segments(candidate).filter(([a, b]) => a.x !== b.x || a.y !== b.y)
      const hits = lines.reduce((count, [a, b]) => count + blockers.filter((box) => crossesBox(a, b, box)).length, 0)
      const crossings = lines.reduce((count, [a, b]) => count + previousSegments.filter(([c, d]) => crossesEdge(a, b, c, d)).length, 0)
      const length = lines.reduce((total, [a, b]) => total + Math.hypot(a.x - b.x, a.y - b.y), 0)
      return hits * 100000 + crossings * 180 + length + (candidate.length - 2) * 35
    }
    const best = candidates.reduce((winner, candidate) => score(candidate) < score(winner) ? candidate : winner)
    previousSegments.push(...segments(best))
    routed.set(edge.id, best.map((point, index) => `${index ? 'L' : 'M'} ${point.x.toFixed(1)} ${point.y.toFixed(1)}`).join(' '))
  }
  return routed
}
