<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use JsonException;
use stdClass;
use Throwable;

/**
 * @phpstan-type RiskInput array{asset_type: string, criticality: int, probability: int, impact: int, internet_exposed: bool, mfa_enabled: bool, encryption_enabled: bool, patches_updated: bool, backups_enabled: bool, monitoring_enabled: bool}
 */
class Equipo1Controller extends Controller
{
    private const CONTROL_WEIGHTS = [
        'mfa_enabled' => 15,
        'encryption_enabled' => 15,
        'patches_updated' => 20,
        'backups_enabled' => 10,
        'monitoring_enabled' => 10,
    ];

    private const ASSET_TYPES = ['server', 'web_app', 'database', 'network'];

    private const MAX_BODY_BYTES = 4096;

    public function evaluate(Request $request): JsonResponse
    {
        $contentType = strtolower(trim(explode(';', $request->headers->get('Content-Type') ?? '')[0]));

        if ($contentType !== 'application/json') {
            return $this->errorResponse('Se requiere contenido JSON.', 415);
        }

        $body = $request->getContent();

        if (strlen($body) > self::MAX_BODY_BYTES) {
            return $this->errorResponse('La solicitud supera el tamaño permitido.', 413);
        }

        try {
            $input = json_decode($body, false, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->errorResponse('El contenido JSON no es válido.', 400);
        }

        if (! $input instanceof stdClass) {
            return $this->errorResponse('Se requiere un objeto JSON.', 422, [
                'body' => ['La estructura no es válida.'],
            ]);
        }

        if ($request->query->count() > 0) {
            return $this->errorResponse('Envíe los datos únicamente en el cuerpo JSON.', 422, [
                'query' => ['No se admiten parámetros en la URL.'],
            ]);
        }

        $data = get_object_vars($input);
        $errors = $this->validateInput($data);

        if ($errors !== []) {
            return $this->errorResponse('Los datos proporcionados no son válidos.', 422, $errors);
        }

        // validateInput comprueba todos los campos y sus tipos antes de evaluar.
        try {
            /** @var RiskInput $data */
            return response()->json($this->assess($data));
        } catch (Throwable $exception) {
            report($exception);

            return $this->errorResponse('No fue posible realizar la evaluación.', 500);
        }
    }

    /**
     * @param  array<array-key, mixed>  $data
     * @return array<string, list<string>>
     */
    public function validateInput(array $data): array
    {
        $numbers = ['criticality', 'probability', 'impact'];
        $booleans = ['internet_exposed', ...array_keys(self::CONTROL_WEIGHTS)];
        $allowed = ['asset_type', ...$numbers, ...$booleans];
        $errors = [];

        if (array_diff(array_keys($data), $allowed) !== []) {
            $errors['fields'] = ['La solicitud contiene campos no permitidos.'];
        }

        $asset = $data['asset_type'] ?? null;

        if (! is_string($asset) || ! in_array($asset, self::ASSET_TYPES, true)) {
            $errors['asset_type'] = ['El tipo de activo no es válido.'];
        }

        foreach ($numbers as $field) {
            $value = $data[$field] ?? null;

            if (! is_int($value) || $value < 1 || $value > 5) {
                $errors[$field] = ['Se requiere un número entero entre 1 y 5.'];
            }
        }

        foreach ($booleans as $field) {
            if (! is_bool($data[$field] ?? null)) {
                $errors[$field] = ['Se requiere un valor booleano true o false.'];
            }
        }

        return $errors;
    }

    public function calculateInitialRisk(int $criticality, int $probability, int $impact): int
    {
        return $criticality * $probability * $impact;
    }

    public function calculateExposure(int $initialRisk, bool $exposed): int
    {
        // El resultado se expresa en décimas para evitar errores de redondeo.
        return $initialRisk * ($exposed ? 12 : 10);
    }

    /**
     * @param  RiskInput  $data
     */
    public function calculateReduction(array $data): int
    {
        $reduction = 0;

        foreach (self::CONTROL_WEIGHTS as $control => $weight) {
            if ($data[$control]) {
                $reduction += $weight;
            }
        }

        return $reduction;
    }

    public function calculateResidualRisk(int $adjustedTenths, int $reduction): int
    {
        return intdiv($adjustedTenths * (100 - $reduction) + 999, 1000);
    }

    public function classifyRisk(int $score, int $minimumLevel = 0): string
    {
        $level = match (true) {
            $score >= 61 => 3,
            $score >= 36 => 2,
            $score >= 16 => 1,
            default => 0,
        };

        return match (max($level, $minimumLevel)) {
            3 => 'CRITICO',
            2 => 'ALTO',
            1 => 'MODERADO',
            default => 'BAJO',
        };
    }

    /**
     * @param  RiskInput  $data
     * @return array{minimum_level: int, findings: list<string>, observations: list<string>}
     */
    public function detectCriticalConditions(array $data): array
    {
        $minimumLevel = 0;
        $findings = [];
        $observations = [];

        if ($data['internet_exposed'] && ! $data['patches_updated']) {
            $minimumLevel = 2;
            $findings[] = 'Sistema expuesto a Internet sin parches actualizados.';
        }

        if ($data['criticality'] === 5 && ! $data['backups_enabled']) {
            $minimumLevel = 2;
            $findings[] = 'Activo de máxima criticidad sin respaldos.';
        }

        if ($data['asset_type'] === 'database' && $data['criticality'] >= 4 && ! $data['encryption_enabled']) {
            $minimumLevel = 2;
            $findings[] = 'Base de datos crítica sin cifrado.';
        }

        if ($data['asset_type'] === 'web_app' && $data['internet_exposed'] && ! $data['mfa_enabled'] && ! $data['patches_updated']) {
            $minimumLevel = 3;
            $findings[] = 'Aplicación web expuesta sin MFA y sin parches.';
        }

        if ($data['internet_exposed'] && ! $data['monitoring_enabled']) {
            $observations[] = 'El sistema está expuesto a Internet sin monitoreo.';
        }

        return [
            'minimum_level' => $minimumLevel,
            'findings' => $findings,
            'observations' => $observations,
        ];
    }

    /**
     * @param  RiskInput  $data
     * @return array{missing_controls: list<string>, recommendations: list<string>}
     */
    public function generateRecommendations(array $data): array
    {
        $controls = [
            'mfa_enabled' => ['MFA', 'Habilitar autenticación multifactor.'],
            'encryption_enabled' => ['Cifrado', 'Implementar cifrado de información.'],
            'patches_updated' => ['Parches de seguridad', 'Actualizar los parches de seguridad.'],
            'backups_enabled' => ['Respaldos', 'Implementar respaldos periódicos.'],
            'monitoring_enabled' => ['Monitoreo', 'Implementar monitoreo de seguridad.'],
        ];
        $missing = [];
        $recommendations = [];

        foreach ($controls as $field => [$name, $message]) {
            if (! $data[$field]) {
                $missing[] = $name;
                $recommendations[] = $message;
            }
        }

        if ($recommendations === []) {
            $recommendations[] = 'Mantener y verificar periódicamente los controles existentes.';
        }

        return [
            'missing_controls' => $missing,
            'recommendations' => $recommendations,
        ];
    }

    /**
     * @param  RiskInput  $data
     * @return array{current_risk: int, projected_risk: int, risk_difference: int, projected_level: string}
     */
    public function simulateMitigation(array $data, int $currentRisk): array
    {
        // La simulación modifica una copia y conserva el escenario original.
        $projectedData = $data;

        foreach (array_keys(self::CONTROL_WEIGHTS) as $control) {
            $projectedData[$control] = true;
        }

        $initialRisk = $this->calculateInitialRisk($data['criticality'], $data['probability'], $data['impact']);
        $adjustedTenths = $this->calculateExposure($initialRisk, $data['internet_exposed']);
        $reduction = $this->calculateReduction($projectedData);
        $projectedRisk = $this->calculateResidualRisk($adjustedTenths, $reduction);
        $conditions = $this->detectCriticalConditions($projectedData);

        return [
            'current_risk' => $currentRisk,
            'projected_risk' => $projectedRisk,
            'risk_difference' => $currentRisk - $projectedRisk,
            'projected_level' => $this->classifyRisk($projectedRisk, $conditions['minimum_level']),
        ];
    }

    public function calculateInternalRisk(int $initialRisk, int $reduction): int
    {
        return $this->calculateResidualRisk(
            $this->calculateExposure($initialRisk, false), $reduction
        );
    }

    /**
     * @param  RiskInput  $data
     * @return array<string, mixed>
     */
    public function assess(array $data): array
    {
        $initialRisk = $this->calculateInitialRisk($data['criticality'], $data['probability'], $data['impact']);
        $adjustedTenths = $this->calculateExposure($initialRisk, $data['internet_exposed']);
        $reduction = $this->calculateReduction($data);
        $residualRisk = $this->calculateResidualRisk($adjustedTenths, $reduction);
        $internalResidualRisk = $this->calculateInternalRisk($initialRisk, $reduction);
        $conditions = $this->detectCriticalConditions($data);
        $level = $this->classifyRisk($residualRisk, $conditions['minimum_level']);

        $status = match ($level) {
            'BAJO' => 'ACEPTABLE',
            'MODERADO' => 'REQUIERE_MEJORAS',
            default => 'INSEGURO',
        };

        return [
            'success' => true,
            'asset_type' => $data['asset_type'],
            'initial_risk' => $initialRisk,
            'adjusted_risk' => $adjustedTenths / 10,
            'risk_reduction_percentage' => $reduction,
            'residual_risk' => $residualRisk,
            'internal_residual_risk' => $internalResidualRisk,
            'exposure_risk_difference' => $residualRisk - $internalResidualRisk,
            'risk_level' => $level,
            'security_status' => $status,
            'critical_findings' => $conditions['findings'],
            'observations' => $conditions['observations'],
            ...$this->generateRecommendations($data),
            'mitigation_simulation' => $this->simulateMitigation($data, $residualRisk),
        ];
    }

    /**
     * @param  array<string, list<string>>  $errors
     */
    private function errorResponse(string $message, int $status, array $errors = []): JsonResponse
    {
        $response = ['success' => false, 'message' => $message];

        if ($errors !== []) {
            $response['errors'] = $errors;
        }

        return response()->json($response, $status);
    }
}
