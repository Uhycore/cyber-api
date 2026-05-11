<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class CowrieController extends Controller
{
    protected string $logPath = '/home/cowrie/cowrie/var/log/cowrie/cowrie.json';

    // GET /api/cowrie/sessions
    // Daftar sesi login penyerang
    public function sessions(Request $request)
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file Cowrie tidak ditemukan'
            ], 404);
        }

        $src_ip = $request->get('src_ip');

        $lines    = $this->readLastLines($this->logPath, 5000);
        $sessions = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data) continue;

            $event = $data['eventid'] ?? '';

            // Hanya ambil event login attempt & session connect
            if (!in_array($event, [
                'cowrie.login.success',
                'cowrie.login.failed',
                'cowrie.session.connect',
                'cowrie.session.closed',
            ])) continue;

            if ($src_ip && ($data['src_ip'] ?? '') !== $src_ip) continue;

            $sessions[] = [
                'timestamp'  => $data['timestamp'] ?? null,
                'event'      => $event,
                'src_ip'     => $data['src_ip'] ?? null,
                'src_port'   => $data['src_port'] ?? null,
                'session'    => $data['session'] ?? null,
                'username'   => $data['username'] ?? null,
                'password'   => $data['password'] ?? null,
                'duration'   => $data['duration'] ?? null,
            ];
        }

        $sessions = array_reverse($sessions);

        return response()->json([
            'success' => true,
            'total'   => count($sessions),
            'data'    => $sessions,
        ]);
    }

    // GET /api/cowrie/commands
    // Command apa saja yang diketik penyerang
    public function commands(Request $request)
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file Cowrie tidak ditemukan'
            ], 404);
        }

        $src_ip  = $request->get('src_ip');
        $session = $request->get('session');

        $lines    = $this->readLastLines($this->logPath, 5000);
        $commands = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data) continue;

            $event = $data['eventid'] ?? '';

            if ($event !== 'cowrie.command.input') continue;

            if ($src_ip && ($data['src_ip'] ?? '') !== $src_ip) continue;
            if ($session && ($data['session'] ?? '') !== $session) continue;

            $commands[] = [
                'timestamp' => $data['timestamp'] ?? null,
                'src_ip'    => $data['src_ip'] ?? null,
                'session'   => $data['session'] ?? null,
                'input'     => $data['input'] ?? null,
            ];
        }

        $commands = array_reverse($commands);

        return response()->json([
            'success' => true,
            'total'   => count($commands),
            'data'    => $commands,
        ]);
    }

    // GET /api/cowrie/downloads
    // File berbahaya yang dicoba diupload/download penyerang
    public function downloads()
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file Cowrie tidak ditemukan'
            ], 404);
        }

        $lines     = $this->readLastLines($this->logPath, 5000);
        $downloads = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data) continue;

            $event = $data['eventid'] ?? '';

            if ($event !== 'cowrie.session.file_download') continue;

            $downloads[] = [
                'timestamp'   => $data['timestamp'] ?? null,
                'src_ip'      => $data['src_ip'] ?? null,
                'session'     => $data['session'] ?? null,
                'url'         => $data['url'] ?? null,
                'filename'    => $data['filename'] ?? null,
                'shasum'      => $data['shasum'] ?? null,
            ];
        }

        $downloads = array_reverse($downloads);

        return response()->json([
            'success' => true,
            'total'   => count($downloads),
            'data'    => $downloads,
        ]);
    }

    // GET /api/cowrie/stats
    // Statistik ringkasan honeypot
    public function stats()
    {
        if (!file_exists($this->logPath)) {
            return response()->json([
                'success' => false,
                'message' => 'Log file Cowrie tidak ditemukan'
            ], 404);
        }

        $lines = $this->readLastLines($this->logPath, 5000);

        $totalSessions  = 0;
        $loginSuccess   = 0;
        $loginFailed    = 0;
        $totalCommands  = 0;
        $totalDownloads = 0;
        $attackers      = [];
        $topPasswords   = [];
        $topUsernames   = [];
        $topCommands    = [];

        foreach ($lines as $line) {
            $data = json_decode($line, true);
            if (!$data) continue;

            $event  = $data['eventid'] ?? '';
            $src_ip = $data['src_ip'] ?? 'unknown';

            switch ($event) {
                case 'cowrie.session.connect':
                    $totalSessions++;
                    $attackers[$src_ip] = ($attackers[$src_ip] ?? 0) + 1;
                    break;

                case 'cowrie.login.success':
                    $loginSuccess++;
                    $user = $data['username'] ?? 'unknown';
                    $pass = $data['password'] ?? 'unknown';
                    $topUsernames[$user] = ($topUsernames[$user] ?? 0) + 1;
                    $topPasswords[$pass] = ($topPasswords[$pass] ?? 0) + 1;
                    break;

                case 'cowrie.login.failed':
                    $loginFailed++;
                    $user = $data['username'] ?? 'unknown';
                    $pass = $data['password'] ?? 'unknown';
                    $topUsernames[$user] = ($topUsernames[$user] ?? 0) + 1;
                    $topPasswords[$pass] = ($topPasswords[$pass] ?? 0) + 1;
                    break;

                case 'cowrie.command.input':
                    $totalCommands++;
                    $cmd = $data['input'] ?? 'unknown';
                    $topCommands[$cmd] = ($topCommands[$cmd] ?? 0) + 1;
                    break;

                case 'cowrie.session.file_download':
                    $totalDownloads++;
                    break;
            }
        }

        // Sort & ambil top 5
        arsort($attackers);
        arsort($topPasswords);
        arsort($topUsernames);
        arsort($topCommands);

        $formatTop = function (array $arr, string $key) {
            $result = [];
            foreach (array_slice($arr, 0, 5, true) as $val => $count) {
                $result[] = [$key => $val, 'count' => $count];
            }
            return $result;
        };

        return response()->json([
            'success' => true,
            'data'    => [
                'total_sessions'   => $totalSessions,
                'login_success'    => $loginSuccess,
                'login_failed'     => $loginFailed,
                'total_commands'   => $totalCommands,
                'total_downloads'  => $totalDownloads,
                'top_attackers'    => $formatTop($attackers, 'ip'),
                'top_passwords'    => $formatTop($topPasswords, 'password'),
                'top_usernames'    => $formatTop($topUsernames, 'username'),
                'top_commands'     => $formatTop($topCommands, 'command'),
            ]
        ]);
    }

    // Helper: baca N baris terakhir dari file
    private function readLastLines(string $path, int $lines): array
    {
        $file = new \SplFileObject($path);
        $file->seek(PHP_INT_MAX);
        $totalLines = $file->key();
        $start      = max(0, $totalLines - $lines);
        $result     = [];
        $file->seek($start);
        while (!$file->eof()) {
            $line = trim($file->current());
            if ($line !== '') $result[] = $line;
            $file->next();
        }
        return $result;
    }
}
