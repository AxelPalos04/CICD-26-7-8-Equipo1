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

    public function test_api_compares_risk_with_an_internal_asset(): void
    {
        $this->postJson(self::ENDPOINT, $this->validPayload())
            ->assertOk()
            ->assertJsonPath('residual_risk', 90)
            ->assertJsonPath('internal_residual_risk', 75);
    }

    public function test_api_returns_control_counts(): void
    {
        $this->postJson(self::ENDPOINT, $this->validPayload())
            ->assertOk()
            ->assertJsonPath('active_controls', 2)
            ->assertJsonPath('inactive_controls', 3);
    }

    public function test_api_indicates_when_a_security_condition_raises_classification(): void
    {
        $data = array_replace($this->validPayload(), [
            'asset_type' => 'database',
            'criticality' => 4,
            'probability' => 1,
            'impact' => 1,
            'internet_exposed' => false,
            'mfa_enabled' => true,
            'encryption_enabled' => false,
            'patches_updated' => true,
            'monitoring_enabled' => true,
        ]);

        $this->postJson(self::ENDPOINT, $data)
            ->assertOk()
            ->assertJsonPath('residual_risk', 2)
            ->assertJsonPath('risk_level', 'ALTO')
            ->assertJsonPath('classification_was_raised', true);
    }

    public function test_api_raises_critical_network_without_monitoring_to_moderate(): void
    {
        $data = array_replace($this->validPayload(), [
            'asset_type' => 'network',
            'criticality' => 4,
            'probability' => 1,
            'impact' => 1,
            'mfa_enabled' => true,
            'patches_updated' => true,
        ]);

        $this->postJson(self::ENDPOINT, $data)
            ->assertOk()
            ->assertJsonPath('risk_level', 'MODERADO')
            ->assertJsonPath('critical_findings', ['Red crítica expuesta sin monitoreo.']);
    }

    public function test_api_error_code_rejects_invalid_fields(): void
    {
        $payload = $this->validPayload();
        $missing = $payload;
        unset($missing['impact']);

        foreach ([$missing, array_replace($payload, ['probability' => 6]), array_replace($payload, ['mfa_enabled' => 'false']), array_replace($payload, ['extra' => true])] as $invalid) {
            $this->postJson(self::ENDPOINT, $invalid)
                ->assertUnprocessable()
                ->assertJsonPath('success', false)
                ->assertJsonPath('error_code', 'VALIDATION_ERROR')
                ->assertJsonMissingPath('trace');
        }
    }

    public function test_api_error_code_rejects_malformed_json(): void
    {
        $this->call('POST', self::ENDPOINT, [], [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'], '{')
            ->assertStatus(400)
            ->assertJsonPath('error_code', 'INVALID_JSON');
    }

    public function test_api_error_code_rejects_oversized_or_wrong_content_type(): void
    {
        $this->call('POST', self::ENDPOINT, [], [], [], ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'], str_repeat(' ', 4097))
            ->assertStatus(413)
            ->assertJsonPath('error_code', 'PAYLOAD_TOO_LARGE');

        $this->call('POST', self::ENDPOINT, [], [], [], ['CONTENT_TYPE' => 'text/plain', 'HTTP_ACCEPT' => 'application/json'], '{}')
            ->assertStatus(415)
            ->assertJsonPath('error_code', 'INVALID_CONTENT_TYPE');
    }

    public function test_api_rejects_query_parameters_and_wrong_method(): void
    {
        $this->postJson(self::ENDPOINT.'?extra=1', $this->validPayload())
            ->assertUnprocessable()
            ->assertJsonPath('error_code', 'VALIDATION_ERROR');

        $this->getJson(self::ENDPOINT)->assertStatus(405);
    }
}
