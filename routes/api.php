<?php

use App\Http\Controllers\Api\AuthController;
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
Route::get('/suricata/alerts', [SuricataController::class, 'alerts']);

// Protected
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'profile']);
});
