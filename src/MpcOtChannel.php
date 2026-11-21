<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later extend(). The base OT is the
 * EC base OT unless $baseOtFn (fn(list<[m0,m1]> $messages, list<int> $choices, MpcOtRandom $rng): list<string>) supplies another.
 */
final class MpcOtChannel
{
    private readonly MpcOtRandom $rng;
    private ?MpcOtExtReceiver $recv = null;
    private ?MpcOtExtSender $send = null;
    private bool $ready = false;
    /** The EC base-OT transcript of the kappa setup transfers (null when a custom base OT is used). */
    public ?array $baseTranscript = null;
    /** TEST-ONLY: mutate the extension receiver's u matrix: fn(list<GMP> $u, int $round): list<GMP>. */
    public mixed $tamperU = null;

    /** @param ?array $binding only sessionId, senderIndex and receiverIndex are used; its round is ignored */
    public function __construct(?MpcOtRandom $rng = null, private readonly mixed $baseOtFn = null, private readonly ?array $binding = null)
    {
        $this->rng = $rng ?? MpcOtRandom::secure();
    }

    private function setup(): void
    {
        $base = $this->binding ?? MpcOt::randomBinding($this->rng, 'x');
        $with = static fn(string $round): array => ['sessionId' => $base['sessionId'], 'senderIndex' => $base['senderIndex'], 'receiverIndex' => $base['receiverIndex'], 'round' => $round];
        $kos = MpcOt::bindingBytes($with('iknp-kos'));
        $r = new MpcOtExtReceiver($this->rng, $kos);
        $sd = new MpcOtExtSender($this->rng, $kos);
        $messages = $r->makeSeeds();
        $sel = $sd->makeSelector();
        if ($this->baseOtFn !== null) {
            $sd->setSeeds(($this->baseOtFn)($messages, $sel, $this->rng));
        } else {
            $res = MpcOt::baseOT($messages, $sel, $this->rng, null, $with('iknp-kappa-setup'));
            $sd->setSeeds($res['received']);
            $this->baseTranscript = $res['transcript'];
        }
        $this->recv = $r;
        $this->send = $sd;
        $this->ready = true;
    }

    public function selector(): \GMP
    {
        if (!$this->ready) {
            $this->setup();
        }
        return $this->send->selector();
    }

    /**
     * @param list<int> $choiceBits @param list<?\GMP> $msg0 @param list<?\GMP> $msg1
     * @return array{received:list<\GMP>,uMatrix:list<\GMP>}
     */
    public function extend(array $choiceBits, array $msg0, array $msg1): array
    {
        if (!$this->ready) {
            $this->setup();
        }
        $m = count($choiceBits);
        if (count($msg0) !== $m || count($msg1) !== $m) {
            throw new \InvalidArgumentException('OtChannel.extend: length mismatch');
        }
        if ($m === 0) {
            return ['received' => [], 'uMatrix' => []];
        }
        MpcOt::checkExtInputs($choiceBits, $msg0, $msg1);
        $this->recv->tamperU = $this->tamperU;
        $b = $this->recv->begin($choiceBits);
        $r = $this->send->respond($b['msg'], $msg0, $msg1);
        return ['received' => $this->recv->finish($b['pending'], $r['y0'], $r['y1']), 'uMatrix' => $b['msg']['u']];
    }
}
