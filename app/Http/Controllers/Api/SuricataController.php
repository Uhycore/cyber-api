<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class SuricataController extends Controller
{
    protected string $logPath = '/var/log/suricata/eve.json';

    // GET /api/suricata/alerts
    public function alerts(Request $request)
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file tidak ditemukan'
            ], 404);
        }

        $severity = $request->get('severity');
        $src_ip   = $request->get('src_ip');

        $lines = $this->readLastLines($this->logPath, 5000);
        $alerts = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data || ($data['event_type'] ?? '') !== 'alert') continue;

            if ($severity && ($data['alert']['severity'] ?? null) != $severity) continue;
            if ($src_ip && ($data['src_ip'] ?? '') !== $src_ip) continue;

            $alerts[] = [
                'timestamp' => $data['timestamp'] ?? null,
                'src_ip'    => $data['src_ip'] ?? null,
                'src_port'  => $data['src_port'] ?? null,
                'dest_ip'   => $data['dest_ip'] ?? null,
                'dest_port' => $data['dest_port'] ?? null,
                'proto'     => $data['proto'] ?? null,
                'signature' => $data['alert']['signature'] ?? null,
                'category'  => $data['alert']['category'] ?? null,
                'severity'  => $data['alert']['severity'] ?? null,
            ];
        }

        $alerts = array_reverse($alerts);

        return response()->json([
            'success' => true,
            'total'   => count($alerts),
            'data'    => $alerts,
        ]);
    }

    // GET /api/suricata/stats
    public function stats()
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file tidak ditemukan'
            ], 404);
        }

        $lines = $this->readLastLines($this->logPath, 5000);

        $high   = 0;
        $medium = 0;
        $low    = 0;
        $total  = 0;
        $attackers = [];
        $categories = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data || ($data['event_type'] ?? '') !== 'alert') continue;

            $total++;
            $severity = $data['alert']['severity'] ?? 0;
            $src_ip   = $data['src_ip'] ?? 'unknown';
            $category = $data['alert']['category'] ?? 'unknown';

            if ($severity == 1) $high++;
            elseif ($severity == 2) $medium++;
            elseif ($severity == 3) $low++;

            // Count per IP
            $attackers[$src_ip] = ($attackers[$src_ip] ?? 0) + 1;

            // Count per category
            $categories[$category] = ($categories[$category] ?? 0) + 1;
        }

        // Top 5 attacker IPs
        arsort($attackers);
        $topAttackers = array_slice($attackers, 0, 5, true);
        $topAttackersList = [];
        foreach ($topAttackers as $ip => $count) {
            $topAttackersList[] = ['ip' => $ip, 'count' => $count];
        }

        // Top 5 categories
        arsort($categories);
        $topCategories = array_slice($categories, 0, 5, true);
        $topCategoriesList = [];
        foreach ($topCategories as $cat => $count) {
            $topCategoriesList[] = ['category' => $cat, 'count' => $count];
        }

        return response()->json([
            'success' => true,
            'data'    => [
                'total'          => $total,
                'high'           => $high,
                'medium'         => $medium,
                'low'            => $low,
                'top_attackers'  => $topAttackersList,
                'top_categories' => $topCategoriesList,
            ]
        ]);
    }

    // Helper
    private function readLastLines(string $path, int $lines): array
    {
        $file = new \SplFileObject($path);
        $file->seek(PHP_INT_MAX);
        $totalLines = $file->key();
        $start  = max(0, $totalLines - $lines);
        $result = [];
        $file->seek($start);
        while (!$file->eof()) {
            $line = trim($file->current());
            if ($line !== '') $result[] = $line;
            $file->next();
        }
        return $result;
    }
    private function readFileLines(string $path): \Generator
    {
        $handle = fopen($path, 'r');
        if (!$handle) return;
        while (!feof($handle)) {
            $line = trim(fgets($handle));
            if ($line !== '') yield $line;
        }
        fclose($handle);
    }

    private function readAllLines(string $path): array
    {
        return file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    }
}
