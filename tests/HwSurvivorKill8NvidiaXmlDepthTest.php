<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Nvidia;
use PHPUnit\Framework\TestCase;

/**
 * Mutation-kill tests for the linear XML nesting pre-scan of the NVIDIA RIM verifier (Nvidia::xmlTooDeep): comments, CDATA,
 * processing instructions and DOCTYPE are skipped exactly, an unterminated construct ends the scan, quotes hide '>' inside a start
 * tag, and the depth limit is 64. Every expectation is derived from the scanner source, not from a run.
 */
final class HwSurvivorKill8NvidiaXmlDepthTest extends TestCase
{
    private static function deep(string $xml): bool
    {
        return (new \ReflectionMethod(Nvidia::class, 'xmlTooDeep'))->invoke(null, $xml);
    }

    private static function tags(int $n): string
    {
        return str_repeat('<a>', $n);
    }

    /** The limit is exactly 64 open elements; a closing tag lowers the depth again. */
    public function testDepthLimitAndEndTags(): void
    {
        $this->assertFalse(self::deep(self::tags(64)));
        $this->assertTrue(self::deep(self::tags(65)));
        $this->assertFalse(self::deep(str_repeat('<a></a>', 40)));
    }

    /** A comment is skipped to its '-->' even when it holds start tags; only a real '<!--' opens one. */
    public function testCommentIsSkippedExactly(): void
    {
        $this->assertFalse(self::deep('<!--' . self::tags(70) . '-->'));
        $this->assertTrue(self::deep('<!-x>' . self::tags(65)));
        $this->assertFalse(self::deep('<!--->' . self::tags(65)));
        $this->assertTrue(self::deep('<!---->' . self::tags(65)));
        $this->assertTrue(self::deep('<!--x<<<-->' . self::tags(64) . '<a>'));
        $this->assertFalse(self::deep('<!--x<<<-->' . self::tags(64)));
    }

    /** CDATA is skipped to its ']]>'; '<![CDATAx' is only a DOCTYPE-like declaration. */
    public function testCdataIsSkippedExactly(): void
    {
        $this->assertFalse(self::deep('<![CDATA[' . self::tags(70) . ']]>'));
        $this->assertTrue(self::deep('<![CDATAx>' . self::tags(65)));
        $this->assertTrue(self::deep('<![CDATA[]]>' . self::tags(65)));
    }

    /** A processing instruction is skipped to its '?>' (searched after the '<?'). */
    public function testProcessingInstructionIsSkippedExactly(): void
    {
        $this->assertFalse(self::deep('<?x' . self::tags(70) . '?>'));
        $this->assertFalse(self::deep('<?>' . self::tags(65)));
        $this->assertTrue(self::deep('<??>' . self::tags(65)));
    }

    /** A declaration ends at its first '>' and is not itself an element. */
    public function testDeclarationIsNotAnElement(): void
    {
        $this->assertFalse(self::deep('<!x>' . self::tags(64)));
        $this->assertTrue(self::deep('<!x>' . self::tags(65)));
        $this->assertTrue(self::deep('<!>' . self::tags(65)));
    }

    /** An unterminated construct ends the scan (false) instead of resuming from an earlier tag. */
    public function testUnterminatedConstructEndsTheScan(): void
    {
        $this->assertFalse(self::deep('<a><a><!--'));
        $this->assertFalse(self::deep('<a><a><![CDATA['));
        $this->assertFalse(self::deep('<a><a><?x'));
        $this->assertFalse(self::deep('<a><a><!x'));
        $this->assertFalse(self::deep(self::tags(64) . '<b'));
    }

    /** The scan resumes after the closing '>' of the previous construct, and a '<>' tag still counts as an opening tag. */
    public function testScanResumesAfterTheTagEnd(): void
    {
        $this->assertFalse(self::deep('<>'));
        $this->assertTrue(self::deep(self::tags(64) . '<>'));
    }

    /** A '>' inside a quoted attribute value does not end the start tag; the quote closes on the same quote character. */
    public function testQuotedGreaterThanDoesNotEndTheTag(): void
    {
        $this->assertTrue(self::deep(self::tags(64) . '<a b=">">'));
        $this->assertFalse(self::deep(self::tags(63) . '<a b=">">'));
    }
}
