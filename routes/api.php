<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\CowrieController;
use App\Http\Controllers\Api\SuricataController;
use App\Http\Controllers\CowrieWebhookController;
use App\Http\Controllers\FCMController;
use Illuminate\Support\Facades\Route;

// routes/api.php
Route::post('/fcm/register', [FCMController::class, 'register']);
Route::post('/cowrie/webhook', [CowrieWebhookController::class, 'handle']);

Route::get('/test', function () {
    return response()->json([
        'success' => true,
        'message' => 'API jalan'
    ]);
});

// Public
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::get('/suricata/alerts', [SuricataController::class, 'alerts']);
Route::get('/suricata/stats', [SuricataController::class, 'stats']);

Route::get('/cowrie/sessions', [CowrieController::class, 'sessions']);
Route::get('/cowrie/commands', [CowrieController::class, 'commands']);
Route::get('/cowrie/downloads', [CowrieController::class, 'downloads']);
Route::get('/cowrie/stats', [CowrieController::class, 'stats']);

// Protected
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'profile']);
});
