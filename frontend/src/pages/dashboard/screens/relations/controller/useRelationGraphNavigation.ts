import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { KeyboardEvent, PointerEvent } from 'react'

const minimumZoom = 0.5
const maximumZoom = 3

interface Size { width: number; height: number }
interface View { x: number; y: number; scale: number }

function centeredOffset(viewport: number, canvas: number) {
  return (viewport - canvas) / 2
}

function containOffset(offset: number, viewport: number, canvas: number) {
  if (canvas <= viewport) return centeredOffset(viewport, canvas)
  return Math.min(0, Math.max(viewport - canvas, offset))
}

export function useRelationGraphNavigation(contentSize: Size) {
  const viewportRef = useRef<HTMLDivElement>(null)
  const pointerRef = useRef<{ id: number; x: number; y: number } | null>(null)
  const [canvas, setCanvas] = useState<Size>(contentSize)
  const [fitScale, setFitScale] = useState(1)
  const [view, setView] = useState<View>({ x: 0, y: 0, scale: 1 })
  const [dragging, setDragging] = useState(false)

  useLayoutEffect(() => {
    const viewport = viewportRef.current
    if (!viewport) return

    const updateSize = () => {
      const width = viewport.clientWidth
      const height = viewport.clientHeight
      if (!width || !height) return
      const nextCanvas = {
        width: Math.max(contentSize.width, width),
        height: Math.max(contentSize.height, height),
      }
      const scale = Math.min(width / nextCanvas.width, height / nextCanvas.height)
      setCanvas(nextCanvas)
      setFitScale(scale)
      setView({
        x: centeredOffset(width, nextCanvas.width * scale),
        y: centeredOffset(height, nextCanvas.height * scale),
        scale,
      })
    }

    updateSize()
    const observer = new ResizeObserver(updateSize)
    observer.observe(viewport)
    return () => observer.disconnect()
  }, [contentSize])

  const zoomAt = useCallback((factor: number, point?: { x: number; y: number }) => {
    const viewport = viewportRef.current
    if (!viewport) return
    const width = viewport.clientWidth
    const height = viewport.clientHeight
    const anchor = point ?? { x: width / 2, y: height / 2 }

    setView((current) => {
      const scale = Math.min(fitScale * maximumZoom, Math.max(fitScale * minimumZoom, current.scale * factor))
      const ratio = scale / current.scale
      return {
        scale,
        x: containOffset(anchor.x - (anchor.x - current.x) * ratio, width, canvas.width * scale),
        y: containOffset(anchor.y - (anchor.y - current.y) * ratio, height, canvas.height * scale),
      }
    })
  }, [canvas, fitScale])

  const panBy = useCallback((dx: number, dy: number) => {
    const viewport = viewportRef.current
    if (!viewport) return
    setView((current) => ({
      ...current,
      x: containOffset(current.x + dx, viewport.clientWidth, canvas.width * current.scale),
      y: containOffset(current.y + dy, viewport.clientHeight, canvas.height * current.scale),
    }))
  }, [canvas])

  useEffect(() => {
    const viewport = viewportRef.current
    if (!viewport) return
    const onWheel = (event: WheelEvent) => {
      event.preventDefault()
      const rect = viewport.getBoundingClientRect()
      zoomAt(event.deltaY < 0 ? 1.12 : 1 / 1.12, { x: event.clientX - rect.left, y: event.clientY - rect.top })
    }
    viewport.addEventListener('wheel', onWheel, { passive: false })
    return () => viewport.removeEventListener('wheel', onWheel)
  }, [zoomAt])

  const fitGraph = useCallback(() => {
    const viewport = viewportRef.current
    if (!viewport) return
    setView({
      x: centeredOffset(viewport.clientWidth, canvas.width * fitScale),
      y: centeredOffset(viewport.clientHeight, canvas.height * fitScale),
      scale: fitScale,
    })
  }, [canvas, fitScale])

  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || (event.target as Element).closest('.relation-node')) return
    event.currentTarget.setPointerCapture(event.pointerId)
    pointerRef.current = { id: event.pointerId, x: event.clientX, y: event.clientY }
    setDragging(true)
  }

  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const pointer = pointerRef.current
    if (!pointer || pointer.id !== event.pointerId) return
    panBy(event.clientX - pointer.x, event.clientY - pointer.y)
    pointerRef.current = { ...pointer, x: event.clientX, y: event.clientY }
  }

  const onPointerEnd = (event: PointerEvent<HTMLDivElement>) => {
    if (pointerRef.current?.id !== event.pointerId) return
    pointerRef.current = null
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId)
    setDragging(false)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.target !== event.currentTarget) return
    const delta: Record<string, [number, number]> = {
      ArrowLeft: [36, 0], ArrowRight: [-36, 0], ArrowUp: [0, 36], ArrowDown: [0, -36],
    }
    if (!delta[event.key]) return
    event.preventDefault()
    panBy(...delta[event.key])
  }

  return {
    viewportRef,
    canvas,
    view,
    dragging,
    zoomPercent: Math.round((view.scale / fitScale) * 100),
    canZoomIn: view.scale < fitScale * maximumZoom - 0.001,
    canZoomOut: view.scale > fitScale * minimumZoom + 0.001,
    zoomIn: () => zoomAt(1.2),
    zoomOut: () => zoomAt(1 / 1.2),
    fitGraph,
    onPointerDown,
    onPointerMove,
    onPointerEnd,
    onKeyDown,
  }
}
