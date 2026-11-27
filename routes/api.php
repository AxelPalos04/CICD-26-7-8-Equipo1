<?php

use App\Http\Controllers\Equipo1Controller;
use App\Http\Controllers\OperationsController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::get('/generate-password', [
    OperationsController::class,
    'generate',
]);

Route::post('/equipo-1/evaluar-riesgos', [
    Equipo1Controller::class,
    'evaluate',
]);
