<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class SuricataController extends Controller
{
    protected string $logPath = '/var/log/suricata/eve.json';

    public function alerts(Request $request)
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file tidak ditemukan'
            ], 404);
        }

        $limit = $request->get('limit', 50);
        $lines = $this->readLastLines($this->logPath, 500);

        $alerts = [];
        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if ($data && isset($data['event_type']) && $data['event_type'] === 'alert') {
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
        }

        $alerts = array_reverse($alerts);
        $alerts = array_slice($alerts, 0, $limit);

        return response()->json([
            'success' => true,
            'total'   => count($alerts),
            'data'    => $alerts,
        ]);
    }

    private function readLastLines(string $path, int $lines): array
    {
        $file = new \SplFileObject($path);
        $file->seek(PHP_INT_MAX);
        $totalLines = $file->key();
        $start = max(0, $totalLines - $lines);
        $result = [];
        $file->seek($start);
        while (!$file->eof()) {
            $line = trim($file->current());
            if ($line !== '') $result[] = $line;
            $file->next();
        }
        return $result;
    }
}
