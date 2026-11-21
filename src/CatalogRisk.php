<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Authorize.php';

/** Risk inputs from the built-in action catalog (catalog-risk.ts). */
final class CatalogRisk
{
    /** Reversibility score per class (1 = fully reversible), the scale the hosted adjudicator uses. */
    public const CATALOG_REVERSIBILITY_SCORE = ['reversible' => 1.0, 'rate_limited' => 0.4, 'costly' => 0.4, 'irreversible' => 0.0];

    private static function number(mixed $v): ?float
    {
        $v = $v instanceof Num ? $v->float() : $v;
        return (is_int($v) || is_float($v)) && is_finite((float)$v) ? (float)$v : null;
    }

    private static function unit(float $x): float
    {
        return min(1.0, max(0.0, $x));
    }

    /**
     * Risk inputs for `$verb` with `$params`, from the catalog and the grant (catalogRisk of the reference): `[]` for an unknown verb (every
     * input is then priced at the worst case). A money-moving verb whose amount is missing or not a finite number >= 0, or whose grant has no
     * positive `kappa`, gets blast radius 1. `$taint` (server-observed, 0..1) is passed through when finite; absent, it is priced at the worst case.
     * @param array<string,mixed>|Obj|null $params
     * @return array<string,float>
     */
    public static function catalogRisk(string $verb, mixed $params, mixed $grant, mixed $taint = null, ?Catalog $catalog = null): array
    {
        $spec = ($catalog ?? new Catalog())->get($verb);
        if ($spec === null) {
            return [];
        }
        $rev = self::CATALOG_REVERSIBILITY_SCORE[$spec['reversibility']] ?? 0.0;
        $blast = self::unit((float)$spec['blastRadius']);
        if (isset($spec['amountField'])) {
            $name = $spec['amountField'];
            $amount = $params instanceof Obj ? ($params->has($name) ? $params->get($name) : null) : (is_array($params) ? ($params[$name] ?? null) : null);
            $risk = Authorize::readEnvelope($grant)?->get('risk_policy');
            $kappa = $risk instanceof Obj ? self::number($risk->get('kappa')) : null;
            $a = self::number($amount);
            $blast = $a !== null && $a >= 0 && $kappa !== null && $kappa > 0 ? self::unit($a / $kappa) : 1.0;
        }
        $out = ['reversibility' => $rev, 'blastRadius' => $blast, 'confidence' => 1.0];
        $t = self::number($taint);
        if ($t !== null) {
            $out['taint'] = self::unit($t);
        }
        return $out;
    }
}
