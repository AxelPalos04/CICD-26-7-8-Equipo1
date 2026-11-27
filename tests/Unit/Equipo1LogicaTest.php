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

    private function riskPayload(): array
    {
        return [
            'asset_type' => 'web_app',
            'criticality' => 5,
            'probability' => 4,
            'impact' => 5,
            'internet_exposed' => true,
            'mfa_enabled' => false,
            'encryption_enabled' => true,
            'patches_updated' => false,
            'backups_enabled' => true,
            'monitoring_enabled' => false,
        ];
    }

    public function test_mitigation_simulates_all_missing_controls(): void
    {
        $controller = new Equipo1Controller;
        $data = $this->riskPayload();

        $this->assertSame([
            'current_risk' => 90,
            'projected_risk' => 36,
            'risk_difference' => 54,
            'projected_level' => 'ALTO',
        ], $controller->simulateMitigation($data, 90));
        $this->assertFalse($data['mfa_enabled']);
    }

    public function test_mitigation_preserves_risk_when_all_controls_are_active(): void
    {
        $controller = new Equipo1Controller;
        $data = array_replace($this->riskPayload(), [
            'mfa_enabled' => true,
            'patches_updated' => true,
            'monitoring_enabled' => true,
        ]);

        $result = $controller->simulateMitigation($data, 36);

        $this->assertSame(36, $result['projected_risk']);
        $this->assertSame(0, $result['risk_difference']);
    }

    public function test_mitigation_recalculates_critical_conditions(): void
    {
        $controller = new Equipo1Controller;
        $data = array_replace($this->riskPayload(), [
            'asset_type' => 'server',
            'probability' => 1,
            'impact' => 1,
            'internet_exposed' => false,
            'mfa_enabled' => true,
            'patches_updated' => true,
            'backups_enabled' => false,
            'monitoring_enabled' => true,
        ]);

        $conditions = $controller->detectCriticalConditions($data);
        $this->assertSame('ALTO', $controller->classifyRisk(2, $conditions['minimum_level']));
        $result = $controller->simulateMitigation($data, 2);
        $this->assertSame(2, $result['projected_risk']);
        $this->assertSame('BAJO', $result['projected_level']);
    }
}
