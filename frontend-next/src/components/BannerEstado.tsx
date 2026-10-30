import type { Escaneo } from "@/lib/tipos";

const TITULO: Record<Escaneo["estado"], string> = {
  pendiente: "Pendiente",
  ejecutando: "En curso",
  completado: "Completado",
  incompleto: "Incompleto",
  fallido: "Fallido",
};

/** Dice en una frase cómo va el escaneo y, si hubo fallos, cuál falló y cuáles no. */
export function BannerEstado({ escaneo }: { escaneo: Escaneo }) {
  return (
    <div className={`banner banner-${escaneo.estado}`} role="status">
      <strong>{TITULO[escaneo.estado]}</strong>
      <span>{escaneo.mensaje}</span>
    </div>
  );
}
