<?php

namespace App\Services;

use Google\Auth\Credentials\ServiceAccountCredentials;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class FCMService
{
    private string $projectId;
    private string $credentialsPath;

    public function __construct()
    {
        // Sesuaikan project ID Firebase kamu
        $this->projectId = config('firebase.project_id');
        $this->credentialsPath = storage_path('app/firebase-credentials.json');
    }

    private function getAccessToken(): string
    {
        $scopes = ['https://www.googleapis.com/auth/firebase.messaging'];
        $credentials = new ServiceAccountCredentials($scopes, $this->credentialsPath);
        $token = $credentials->fetchAuthToken();
        return $token['access_token'];
    }

    public function sendToToken(
        string $fcmToken,
        string $title,
        string $body,
        array $data = []
    ): bool {
        try {
            $accessToken = $this->getAccessToken();

            $response = Http::withHeaders([
                'Authorization' => "Bearer {$accessToken}",
                'Content-Type'  => 'application/json',
            ])->post(
                "https://fcm.googleapis.com/v1/projects/{$this->projectId}/messages:send",
                [
                    'message' => [
                        'token'        => $fcmToken,
                        'notification' => [
                            'title' => $title,
                            'body'  => $body,
                        ],
                        'data'         => array_map('strval', $data), // FCM data harus string
                        'android'      => [
                            'priority' => 'high',
                            'notification' => [
                                'color'        => '#FF4D4D',
                                'sound'        => 'default',
                                'click_action' => 'FLUTTER_NOTIFICATION_CLICK',
                            ],
                        ],
                    ],
                ]
            );

            if ($response->successful()) {
                Log::info('[FCM] Notif terkirim ke token: ' . substr($fcmToken, 0, 20) . '...');
                return true;
            }

            Log::error('[FCM] Gagal kirim: ' . $response->body());
            return false;
        } catch (\Exception $e) {
            Log::error('[FCM] Exception: ' . $e->getMessage());
            return false;
        }
    }

    // Kirim ke semua device yang terdaftar
    public function broadcastAll(string $title, string $body, array $data = []): void
    {
        $tokens = \App\Models\DeviceToken::all()->pluck('fcm_token');

        foreach ($tokens as $token) {
            $this->sendToToken($token, $title, $body, $data);
        }
    }
}
