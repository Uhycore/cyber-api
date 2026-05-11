<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\CowrieController;
use App\Http\Controllers\Api\SuricataController;
use Illuminate\Support\Facades\Route;


Route::get('/test', function () {
    return response()->json([
        'success' => true,
        'message' => 'API jalan'
    ]);
});

// Public
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

Route::prefix('suricata')->group(function () {
    Route::get('/alerts', [SuricataController::class, 'alerts']);
    Route::get('/stats', [SuricataController::class, 'stats']);
});

Route::prefix('cowrie')->group(function () {
    Route::get('/sessions',  [CowrieController::class, 'sessions']);
    Route::get('/commands',  [CowrieController::class, 'commands']);
    Route::get('/downloads', [CowrieController::class, 'downloads']);
    Route::get('/stats',     [CowrieController::class, 'stats']);
});

// Protected
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'profile']);
});
