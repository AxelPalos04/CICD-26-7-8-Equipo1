<?php

namespace Tests\Feature;

use Tests\TestCase;

class Equipo1ApiTest extends TestCase
{
    private const ENDPOINT = '/api/equipo-1/evaluar-riesgos';

    private function validPayload(): array
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

    public function test_api_evaluates_a_valid_critical_asset(): void
    {
        $this->postJson(self::ENDPOINT, $this->validPayload())
            ->assertOk()
            ->assertJsonPath('success', true)
            ->assertJsonPath('initial_risk', 100)
            ->assertJsonPath('adjusted_risk', 120)
            ->assertJsonPath('risk_reduction_percentage', 25)
            ->assertJsonPath('residual_risk', 90)
            ->assertJsonPath('risk_level', 'CRITICO')
            ->assertJsonPath('security_status', 'INSEGURO')
            ->assertJsonPath('missing_controls', ['MFA', 'Parches de seguridad', 'Monitoreo'])
            ->assertJsonStructure(['critical_findings', 'observations', 'recommendations']);
    }

    public function test_api_rejects_a_numeric_string(): void
    {
        $payload = $this->validPayload();
        $payload['probability'] = '4';

        $this->postJson(self::ENDPOINT, $payload)
            ->assertUnprocessable()
            ->assertJsonPath('success', false)
            ->assertJsonValidationErrors(['probability'])
            ->assertJsonMissingPath('trace');
    }

    public function test_api_returns_full_mitigation_simulation(): void
    {
        $this->postJson(self::ENDPOINT, $this->validPayload())
            ->assertOk()
            ->assertJsonPath('mitigation_simulation.current_risk', 90)
            ->assertJsonPath('mitigation_simulation.projected_risk', 36)
            ->assertJsonPath('mitigation_simulation.risk_difference', 54)
            ->assertJsonPath('mitigation_simulation.projected_level', 'ALTO');
    }

    public function test_api_reports_no_additional_mitigation_with_all_controls(): void
    {
        $data = array_replace($this->validPayload(), [
            'mfa_enabled' => true,
            'patches_updated' => true,
            'monitoring_enabled' => true,
        ]);

        $this->postJson(self::ENDPOINT, $data)
            ->assertOk()
            ->assertJsonPath('residual_risk', 36)
            ->assertJsonPath('mitigation_simulation.projected_risk', 36)
            ->assertJsonPath('mitigation_simulation.risk_difference', 0);
    }
}
