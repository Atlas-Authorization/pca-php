<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Base of the coded failures of the durable stores: `codeName` is stable, the message is `<code>: <text>`. */
abstract class CodedStoreError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($codeName . ': ' . $message);
    }
}

/** The typed failure of every store-backed ledger operation. */
final class LedgerStoreError extends CodedStoreError
{
}

/** The typed failure of every store-backed bond operation. */
final class BondStoreError extends CodedStoreError
{
}

/** The typed failure of the aggregate budget ledger. */
final class BudgetLedgerError extends CodedStoreError
{
}

/** Shared helpers of the durable stores. */
final class StoreErrors
{
    /** The stable code of an error: its `codeName` for a coded error, `RangeError` for an argument error, else `Error`. */
    public static function codeOf(\Throwable $e): string
    {
        if ($e instanceof CodedStoreError) {
            return $e->codeName;
        }
        return $e instanceof \RangeException ? 'RangeError' : 'Error';
    }
}
