<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Tests\Unit;

use FilesystemIterator;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;

/**
 * Rendered docs are English — the docblocks an IDE shows for this package's types and for their public and
 * protected constants, properties (promoted ones included) and methods. The translation measured this same
 * dump (registry `korean-api-docs-in-published-packages`); this keeps a Korean docblock from coming back.
 */
final class RenderedDocsEnglishTest extends TestCase
{
    private const HANGUL = '/[\x{AC00}-\x{D7A3}]/u';

    /**
     * Every type under `src/`, loaded through the package's own PSR-4 map.
     *
     * @return list<class-string>
     */
    private static function types(): array
    {
        $src = \dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'src';
        $types = [];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
        foreach ($files as $file) {
            if (!$file instanceof SplFileInfo || !$file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }
            $relative = substr($file->getPathname(), \strlen($src) + 1, -4);
            $name = 'Xzawed\\Keycloak\\' . str_replace(['/', '\\'], '\\', $relative);
            if (class_exists($name) || interface_exists($name) || trait_exists($name) || enum_exists($name)) {
                $types[] = $name;
            }
        }
        sort($types);

        return $types;
    }

    /**
     * @return list<string>
     */
    private static function hangulLines(string $where, string|false $doc): array
    {
        if ($doc === false) {
            return [];
        }
        $hits = [];
        foreach (explode("\n", $doc) as $line) {
            if (preg_match(self::HANGUL, $line) === 1) {
                $hits[] = $where . ': ' . trim($line);
            }
        }

        return $hits;
    }

    /**
     * @param class-string $type
     *
     * @return list<string>
     */
    private static function dump(string $type): array
    {
        $class = new ReflectionClass($type);
        $hits = self::hangulLines($type, $class->getDocComment());
        foreach ($class->getReflectionConstants() as $constant) {
            if (!$constant->isPrivate() && $constant->getDeclaringClass()->getName() === $type) {
                $hits = [...$hits, ...self::hangulLines($type . '::' . $constant->getName(), $constant->getDocComment())];
            }
        }
        foreach ($class->getProperties() as $property) {
            if (!$property->isPrivate() && $property->getDeclaringClass()->getName() === $type) {
                $hits = [...$hits, ...self::hangulLines($type . '::$' . $property->getName(), $property->getDocComment())];
            }
        }
        foreach ($class->getMethods() as $method) {
            if (!$method->isPrivate() && $method->getDeclaringClass()->getName() === $type) {
                $hits = [...$hits, ...self::hangulLines($type . '::' . $method->getName() . '()', $method->getDocComment())];
            }
        }

        return $hits;
    }

    public function testTheDetectorFindsHangulInADocblock(): void
    {
        self::assertSame(['x: * 한글'], self::hangulLines('x', "/**\n * 한글\n */"));
        self::assertSame([], self::hangulLines('x', "/**\n * English\n */"));
        self::assertSame([], self::hangulLines('x', false));
    }

    public function testPublicDocblocksAreEnglish(): void
    {
        $types = self::types();
        self::assertGreaterThan(20, \count($types), 'an empty walk would pass vacuously');
        $hits = [];
        foreach ($types as $type) {
            $hits = [...$hits, ...self::dump($type)];
        }
        self::assertSame([], $hits);
    }
}
