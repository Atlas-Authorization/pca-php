<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** The FN-DSA primitive behind {@see Fndsa}: verify(pk, msg, sig): bool is required; sign(sk, msg): string and keygen(): array{pk,sk} are optional. */
final class FalconBackend
{
    /**
     * @param \Closure(string,string,string):bool $verify
     * @param (\Closure(string,string):string)|null $sign
     * @param (\Closure():array{pk:string,sk:string})|null $keygen
     * @param (\Closure(string,string,string):string)|null $signSeeded (sk, msg, 32-byte sign seed): deterministic signing for known-answer replay
     */
    public function __construct(public readonly \Closure $verify, public readonly ?\Closure $sign = null, public readonly ?\Closure $keygen = null, public readonly ?\Closure $signSeeded = null)
    {
    }
}
