<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\LessFfi;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** Round r9: faults injected into the internal-error catches (each must fail closed, never accept). */
final class R9FaultInjectionTest extends TestCase
{
    public function testDeepEqualityFaultIsNotEqual(): void
    {
        // host arrays with non-list keys: element reads raise warnings, which a host error handler turns into exceptions
        $c = new Obj();
        $env = new Obj();
        $env->set('v', ['a' => 1]);
        $c->set('env', $env);
        $c->set('action', Json::parseLax('{"verb":"r","resource":"x","params":{}}'));
        $eq = new Obj();
        $eq->set('field', 'env.v');
        $eq->set('op', 'eq');
        $eq->set('value', ['b' => 1]);
        $ne = new Obj();
        $ne->set('field', 'env.v');
        $ne->set('op', 'ne');
        $ne->set('value', ['b' => 1]);
        set_error_handler(static function (int $no, string $str, string $file, int $line): never {
            throw new \ErrorException($str, 0, $no, $file, $line);
        });
        try {
            $this->assertSame('false', Predicates::evaluateConditionTri($eq, $c));
            $this->assertSame('true', Predicates::evaluateConditionTri($ne, $c));
        } finally {
            restore_error_handler();
        }
    }

    public function testLessVerifierFaultIsNotAccepted(): void
    {
        if (!extension_loaded('FFI')) {
            $this->markTestSkipped('FFI is not available');
        }
        try {
            // an FFI handle that does not carry the verifier symbol: calling it raises an Error
            $stub = \FFI::cdef('int abs(int x);');
        } catch (\Throwable) {
            $this->markTestSkipped('FFI::cdef is not enabled');
        }
        $ffi = new \ReflectionProperty(LessFfi::class, 'ffi');
        $tried = new \ReflectionProperty(LessFfi::class, 'tried');
        $oldFfi = $ffi->getValue();
        $oldTried = $tried->getValue();
        try {
            $ffi->setValue(null, $stub);
            $tried->setValue(null, true);
            $this->assertFalse(LessFfi::verify(str_repeat("\1", LessFfi::PUBLIC_KEY_BYTES), 'm', str_repeat("\2", LessFfi::SIGNATURE_MAX_BYTES)));
        } finally {
            $ffi->setValue(null, $oldFfi);
            $tried->setValue(null, $oldTried);
        }
    }

    public function testLessVerifierWithoutTheLibraryRejects(): void
    {
        $ffi = new \ReflectionProperty(LessFfi::class, 'ffi');
        $tried = new \ReflectionProperty(LessFfi::class, 'tried');
        $oldFfi = $ffi->getValue();
        $oldTried = $tried->getValue();
        try {
            $ffi->setValue(null, null);
            $tried->setValue(null, true); // the library was looked for and not found
            $this->assertFalse(LessFfi::verify(str_repeat("\1", LessFfi::PUBLIC_KEY_BYTES), 'm', str_repeat("\2", LessFfi::SIGNATURE_MAX_BYTES)));
        } finally {
            $ffi->setValue(null, $oldFfi);
            $tried->setValue(null, $oldTried);
        }
    }
}
