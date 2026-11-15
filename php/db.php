<?php
declare(strict_types=1);

final class DB
{
    private static ?PDO $pdo = null;

    public static function get(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }

        $cfg = self::config();

        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
            $cfg['host'], (int) $cfg['port'], $cfg['name']
        );

        try {
            self::$pdo = new PDO($dsn, $cfg['user'], $cfg['pass'], [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            error_log('[BlitzIQ] DB connection failed: ' . $e->getMessage());
            throw new RuntimeException('Cannot connect to the database. Please try again later.');
        }

        return self::$pdo;
    }

    public static function close(): void
    {
        self::$pdo = null;
    }

    private static function config(): array
    {
        $defaults = [
            'host' => '127.0.0.1',
            'port' => 3306,
            'name' => 'QUIZ',
            'user' => 'root',
            'pass' => '',
        ];
        $local = __DIR__ . '/config.local.php';
        return file_exists($local) ? array_merge($defaults, require $local) : $defaults;
    }
}
