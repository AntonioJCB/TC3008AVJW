from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Obs:
    """Una observación normalizada (fila de `observaciones` + su activo y su fuente)."""

    id: str
    activo_id: str
    tipo: str  # dominio | subdominio | ip | correo | servicio
    valor: str
    atributo: str
    datos: dict[str, Any]
    fuente: str  # fuentes_osint.nombre
    fuente_id: str
    observado_en: str | None = None


@dataclass(frozen=True, slots=True)
class Regla:
    """Una fila de `reglas_riesgo`. El peso y la severidad se calibran en la base de datos."""

    id: str
    codigo: str
    nombre: str
    categoria: str
    severidad: str
    peso: int
    esta_activa: bool = True


@dataclass(slots=True)
class Candidato:
    """Lo que devuelve un evaluador: un activo que cumple la regla y su evidencia."""

    activo_id: str
    observaciones: list[Obs]
    detalle: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Hallazgo:
    activo_id: str
    regla_id: str
    regla_codigo: str
    fuente_id: str  # fuente principal; todas las fuentes quedan en la evidencia
    categoria: str
    severidad: str
    confianza: float
    evidencia: dict[str, Any]

    def como_dict(self) -> dict[str, Any]:
        return {
            "activo_id": self.activo_id,
            "regla_id": self.regla_id,
            "fuente_id": self.fuente_id,
            "categoria": self.categoria,
            "severidad": self.severidad,
            "confianza": self.confianza,
            "evidencia": self.evidencia,
        }


@dataclass(slots=True)
class Puntaje:
    puntaje_global: int
    infraestructura: int
    identidad_digital: int
    configuracion: int
    fuga_de_datos: int
    #: True si alguna fuente no terminó: el puntaje no vio todo y puede estar subestimado.
    es_parcial: bool
    fuentes_faltantes: list[str]
    cobertura: dict[str, Any]
    version_motor: str

    def como_dict(self) -> dict[str, Any]:
        return {
            "puntaje_global": self.puntaje_global,
            "infraestructura": self.infraestructura,
            "identidad_digital": self.identidad_digital,
            "configuracion": self.configuracion,
            "fuga_de_datos": self.fuga_de_datos,
            "es_parcial": self.es_parcial,
            "fuentes_faltantes": self.fuentes_faltantes,
            "cobertura": self.cobertura,
            "version_motor": self.version_motor,
        }


@dataclass(slots=True)
class ResultadoRiesgo:
    hallazgos: list[Hallazgo]
    puntaje: Puntaje
