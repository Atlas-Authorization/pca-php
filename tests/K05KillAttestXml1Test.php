<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Xml;
use Atlas\Pca\Attest\XmlDocument;
use Atlas\Pca\Attest\XmlError;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for Atlas\Pca\Attest\Xml (PCA 0.5 mutation baseline). Every PHP warning is turned into an exception so an
 * out-of-range string offset read (the off-by-one mutants) cannot pass silently. Reason strings are asserted exactly.
 */
final class K05KillAttestXml1Test extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $str, string $file, int $line): bool {
            throw new \ErrorException($str, 0, $no, $file, $line);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function p(string $xml): XmlDocument
    {
        return Xml::parse($xml);
    }

    private function err(string $xml): string
    {
        try {
            Xml::parse($xml);
        } catch (XmlError $e) {
            return $e->getMessage();
        }
        $this->fail('no XmlError for ' . $xml);
    }

    /** @return array<string,array{string,string}> */
    public static function errors(): array
    {
        return [
            'empty entity name' => ['<a>&;</a>', 'unknown entity &;'],
            'unterminated entity' => ['<a>&amp</a>', 'unterminated entity reference'],
            'unknown entity' => ['<a>&foo;</a>', 'unknown entity &foo;'],
            'lt in attribute' => ['<a x="<"/>', "'<' in an attribute value"],
            'text outside root' => ['x<a/>', 'text outside the root element'],
            'dash dash dash gt is not a comment end' => ['<a><!--->x</a>', 'unterminated comment'],
            'unterminated comment nested' => ['<a><b><!-- x', 'unterminated comment'],
            'unterminated cdata nested' => ['<a><b><![CDATA[x', 'bad CDATA section'],
            'cdata outside root' => ['<![CDATA[x]]><a/>', 'bad CDATA section'],
            'unterminated PI nested' => ['<a><b><?x', 'unterminated processing instruction'],
            'question gt is not a PI end' => ['<?><a/>', 'unterminated processing instruction'],
            'unterminated declaration' => ['<a><!DOCTYPE', 'unterminated declaration'],
            'end tag no name' => ['<a></ >', 'bad end tag'],
            'end tag empty' => ['<a></>', 'bad end tag'],
            'end tag eof' => ['<a></a', 'bad end tag'],
            'end tag junk' => ['<a></a x>', 'bad end tag'],
            'mismatched' => ['<a></b>', 'mismatched end tag </b>'],
            'end tag with empty stack' => ['</a>', 'mismatched end tag </a>'],
            'bad start tag' => ['<a><1/></a>', 'bad start tag'],
            'two roots' => ['<a/><b/>', 'more than one root element'],
            'unterminated start tag' => ['<a', 'unterminated start tag'],
            'unterminated start tag after attr' => ['<a x="1"', 'unterminated start tag'],
            'no whitespace before attribute' => ['<a x="1"y="2"/>', 'missing whitespace before an attribute'],
            'bad attribute name' => ['<a 1="x"/>', 'bad attribute name'],
            'attribute without value' => ['<a x/>', 'attribute without a value'],
            'attribute without value then another' => ['<a x y="1"/>', 'attribute without a value'],
            'attribute eof after name' => ['<a x', 'attribute without a value'],
            'unquoted attribute' => ['<a x=1/>', 'unquoted attribute value'],
            'attribute eof after equals' => ['<a x=', 'unquoted attribute value'],
            'unterminated attribute' => ['<a x="1/>', 'unterminated attribute value'],
            'duplicate attribute' => ['<a x="1" x="2"/>', 'duplicate attribute x'],
            'undeclare prefix' => ['<a xmlns:p=""/>', 'namespace prefix cannot be undeclared'],
            'unbound element prefix' => ['<p:a/>', 'unbound namespace prefix p'],
            'unbound attribute prefix' => ['<a p:x="1"/>', 'unbound namespace prefix p'],
            'unclosed' => ['<a><b>', 'unclosed element <b>'],
            'empty' => ['', 'no root element'],
            'only a comment' => ['<!-- c -->', 'no root element'],
        ];
    }

    #[DataProvider('errors')]
    public function testErrorMessages(string $xml, string $msg): void
    {
        $this->assertSame($msg, $this->err($xml));
    }

    // ---- tree accessors ---------------------------------------------------------------------------------------------------------

    public function testElementChildrenFiltersByNamespaceAndLocal(): void
    {
        $r = self::p('<r xmlns:p="u"><p:a/><b/><p:c/></r>')->root;
        $this->assertCount(3, $r->elementChildren());
        $ns = $r->elementChildren('u');
        $this->assertCount(2, $ns);
        $this->assertSame('a', $ns[0]->local);
        $this->assertSame('c', $ns[1]->local);
        $none = $r->elementChildren('');
        $this->assertCount(1, $none);
        $this->assertSame('b', $none[0]->local);
        $this->assertCount(1, $r->elementChildren('u', 'c'));
        $this->assertCount(1, $r->elementChildren(null, 'b'));
    }

    public function testDescendantsCollectsNestedMatchesInOrder(): void
    {
        $r = self::p('<r xmlns="u"><a><a/><x><a/></x></a><a/></r>')->root;
        $d = $r->descendants('u', 'a');
        $this->assertCount(4, $d);
        $a1 = $r->children[0];
        $this->assertSame($a1, $d[0]);
        $this->assertSame($a1->children[0], $d[1]);
        $this->assertSame($a1->children[1]->children[0], $d[2]);
        $this->assertSame($r->children[1], $d[3]);
    }

    public function testTextContentConcatenatesNestedText(): void
    {
        $r = self::p('<r>x<a>y<b>z</b></a>w</r>')->root;
        $this->assertSame('xyzw', $r->textContent());
    }

    // ---- entities, character references, attribute normalisation ---------------------------------------------------------------

    public function testEntitiesAndCharacterReferences(): void
    {
        $r = self::p('<a>a&#x20AC;b&#8364;c&amp;d&lt;&gt;&quot;&apos;</a>')->root;
        $this->assertSame("a\u{20AC}b\u{20AC}c&d<>\"'", $r->textContent());
    }

    public function testCharacterReferenceLeadingZerosAreIgnored(): void
    {
        $r = self::p('<a>&#x0000000041;&#00000000065;</a>')->root;
        $this->assertSame('AA', $r->textContent());
    }

    public function testAttributeValueNormalisationAndEntities(): void
    {
        $r = self::p("<a x=\"a\tb\nc\rd\" y=\"a&amp;b\" z='1'/>")->root;
        $this->assertSame('a b c d', $r->getAttribute('x'));
        $this->assertSame('a&b', $r->getAttribute('y'));
        $this->assertSame('1', $r->getAttribute('z'));
        $r2 = self::p("<a x=\"a\tb\"/>")->root;
        $this->assertSame('a b', $r2->getAttribute('x'));
    }

    public function testUnescapeTextKeepsWhitespaceAndLt(): void
    {
        $m = new \ReflectionMethod(Xml::class, 'unescape');
        $this->assertSame("a&\tb", $m->invoke(null, "a&amp;\tb", false));
        $this->assertSame('a&b', $m->invoke(null, 'a&amp;b', false));
        $this->assertSame('<&', $m->invoke(null, '<&amp;', false));
        $this->assertSame('a b', $m->invoke(null, "a\tb", true));
    }

    // ---- comments / CDATA / PIs / DOCTYPE ---------------------------------------------------------------------------------------

    public function testCommentIsRecordedAndSkippedExactly(): void
    {
        $d = self::p('<a><!--c--></a>');
        $this->assertSame(['XML comments are not permitted'], $d->violations);
        $this->assertSame('', $d->root->textContent());
        $d = self::p('<a><!--c-->x</a>');
        $this->assertSame('x', $d->root->textContent());
        $this->assertSame(['XML comments are not permitted'], $d->violations);
        $d = self::p('<a><!----></a>');
        $this->assertSame(['XML comments are not permitted'], $d->violations);
        $d = self::p('<!--c--><a/>');
        $this->assertSame(['XML comments are not permitted'], $d->violations);
        $this->assertSame('a', $d->root->qname);
    }

    public function testCdataSections(): void
    {
        $d = self::p('<a><b><![CDATA[xyz]]>t</b></a>');
        $this->assertSame([], $d->violations);
        $b = $d->root->children[0];
        $this->assertSame(['xyz', 't'], $b->children);
        $this->assertSame([$b], $d->root->children);
        $this->assertSame([''], self::p('<a><![CDATA[]]></a>')->root->children);
        $this->assertSame('xtail text here', self::p('<a><![CDATA[x]]>tail text here</a>')->root->textContent());
    }

    public function testProcessingInstructions(): void
    {
        $d = self::p('<?xml version="1.0"?><a/>');
        $this->assertSame(['XML processing instructions are not permitted'], $d->violations);
        $this->assertSame('a', $d->root->qname);
        $d = self::p('<a><?p?>x</a>');
        $this->assertSame('x', $d->root->textContent());
        $this->assertSame(['XML processing instructions are not permitted'], $d->violations);
        $d = self::p('<??><a/>');
        $this->assertSame(['XML processing instructions are not permitted'], $d->violations);
        $this->assertSame('a', $d->root->qname);
        $d = self::p('<?x?><a/>');
        $this->assertSame('a', $d->root->qname);
    }

    public function testDoctypeDeclarations(): void
    {
        foreach (['<!DOCTYPE a><a/>', '<!DOCTYPE a [<!ENTITY x "y">]><a/>', '<!><a/>'] as $x) {
            $d = self::p($x);
            $this->assertSame(['DTD / DOCTYPE is not permitted'], $d->violations, $x);
            $this->assertSame('a', $d->root->qname, $x);
        }
        $d = self::p('<a>x[<!DOCTYPE b></a>');
        $this->assertSame(['DTD / DOCTYPE is not permitted'], $d->violations);
        $this->assertSame('x[', $d->root->textContent());
    }

    // ---- namespaces and attributes ----------------------------------------------------------------------------------------------

    public function testNamespaceScopes(): void
    {
        $a = self::p('<a xmlns="u"><b/></a>')->root;
        $this->assertSame('u', $a->ns);
        $this->assertSame('u', $a->children[0]->ns);
        $r = self::p('<a xmlns="u"><b xmlns=""/></a>')->root;
        $this->assertSame([], $r->children[0]->scope);
        $this->assertSame('', $r->children[0]->ns);
        $this->assertSame([], self::p('<a xmlns=""/>')->root->scope);
    }

    public function testXmlAttributeViolationsAreCaseInsensitive(): void
    {
        $d = self::p('<a xml:lang="en"/>');
        $this->assertSame(["xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)"], $d->violations);
        $d = self::p('<a xmlns:XML="u" XML:lang="en"/>');
        $this->assertSame(["xml:* attribute 'XML:lang' is not permitted (C14N 1.1 profile)"], $d->violations);
    }

    // ---- canonical form ---------------------------------------------------------------------------------------------------------

    public function testCanonicalEscaping(): void
    {
        $r = self::p("<a x=\"a&amp;b&lt;c&quot;d&#9;e&#10;f&#13;g&gt;h\">p&amp;q&lt;r&gt;s&#13;t\"u</a>")->root;
        $this->assertSame(
            '<a x="a&amp;b&lt;c&quot;d&#x9;e&#xA;f&#xD;g>h">p&amp;q&lt;r&gt;s&#xD;t"u</a>',
            Xml::canonicalize($r)
        );
    }

    public function testCanonicalNamespaceDeclarations(): void
    {
        $this->assertSame('<a><b></b></a>', Xml::canonicalize(self::p('<a><b/></a>')->root));
        $this->assertSame('<a></a>', Xml::canonicalize(self::p('<a xmlns=""/>')->root));
        $this->assertSame(
            '<a xmlns="u"><b xmlns=""></b></a>',
            Xml::canonicalize(self::p('<a xmlns="u"><b xmlns=""/></a>')->root)
        );
        $this->assertSame(
            '<a xmlns="d" xmlns:10="x" xmlns:9="y" xmlns:a="1" xmlns:b="2"></a>',
            Xml::canonicalize(self::p('<a xmlns:b="2" xmlns:a="1" xmlns:10="x" xmlns:9="y" xmlns="d"/>')->root)
        );
    }
}
