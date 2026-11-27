<?php

namespace Tests\Unit;

use App\Http\Controllers\Equipo1Controller;
use PHPUnit\Framework\TestCase;

class Equipo1LogicaTest extends TestCase
{
    public function test_initial_risk_multiplies_the_three_factors(): void
    {
        $controller = new Equipo1Controller;

        $this->assertSame(100, $controller->calculateInitialRisk(5, 4, 5));
    }

    public function test_residual_risk_rounds_up(): void
    {
        $controller = new Equipo1Controller;

        $this->assertSame(1, $controller->calculateResidualRisk(12, 70));
        $this->assertSame(90, $controller->calculateResidualRisk(1200, 25));
    }
}
