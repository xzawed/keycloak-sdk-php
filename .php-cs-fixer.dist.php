<?php
$finder = PhpCsFixer\Finder::create()->in([__DIR__ . '/src', __DIR__ . '/tests']);
return (new PhpCsFixer\Config())
    ->setRules(['@PER-CS2.0' => true, '@PSR12' => true, 'declare_strict_types' => true])
    ->setFinder($finder);
