<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * What a guarded dispatch receives so it can carry the proof to the resource server (the reference's PcaCall): the encoded PCActn JSON, the PCActn and the
 * headers that carry it, and the provenance bundle of the action (send it as body member `pca_provenance` when it is not in `headers`).
 * {@see Adapters::bridgeToolCall} returns the same four members as an array; {@see fromBridge} lifts that into this value.
 */
final class PcaCall
{
    /** @param array<string,string> $headers */
    public function __construct(public readonly string $encoded, public readonly Obj $pcactn, public readonly array $headers, public readonly ?Obj $provenance = null)
    {
    }

    /** @param array{encoded:string,pcactn:Obj,headers:array<string,string>,provenance?:?Obj} $call */
    public static function fromBridge(array $call): self
    {
        return new self($call['encoded'], $call['pcactn'], $call['headers'], $call['provenance'] ?? null);
    }
}
