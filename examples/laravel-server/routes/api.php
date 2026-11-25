<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Runs only when the request carries a PCA-Action proof that authorizes exactly this operation.
Route::post('/refunds', fn (Request $request) => response()->json(['refunded' => true, 'amount' => $request->input('amount')], 201))
    ->middleware('pca');
