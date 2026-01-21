pipeline {
    //agent any
    agent {
        docker { 
            image 'python:3.10-slim' 
            // Esto asegura que el contenedor se ejecute como root para poder instalar cosas si hace falta
            args '-u root' 
        }
    }

    environment {
        // --- DEFECTDOJO CONFIG ---
        DOJO_URL = 'http://localhost:8083'
        DOJO_PRODUCT = 'PyGoat'
        DOJO_ENGAGEMENT = 'Jenkins CI Scan'
        // IMPORTANTE: Aquí va el ID de la credencial de Jenkins, NO la clave real
        DOJO_API_KEY = credentials('defectdojo-api-key')

        // --- DEPENDENCY-TRACK CONFIG ---
        DT_URL = 'http://localhost:8081'
        // IMPORTANTE: Aquí va el ID de la credencial de Jenkins, NO la clave real
        DT_API_KEY = credentials('deptrack-api-key')
        DT_PROJECT_NAME = 'PyGoat'
        DT_PROJECT_VERSION = '1.0.0'
    }

    stages {
        stage('Preparación') {
            steps {
		// 1. Instalar librerías del sistema necesarias para compilar psycopg2
                // Como estamos en un contenedor Docker 'slim', necesitamos esto:
                sh 'apt-get update && apt-get install -y libpq-dev gcc python3-dev musl-dev curl'

                // 2. Crear entorno virtual
                sh 'python3 -m venv venv'

                // 3. Instalar dependencias de Python
                sh '. venv/bin/activate && pip install -r requirements.txt'

		// 4. Instalar herramientas de seguridad
                sh '. venv/bin/activate && pip install bandit cyclonedx-bom requests'
                
                // 5. Instalar Gitleaks
                sh 'curl -sS -L https://github.com/zricethezav/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar xz gitleaks || true'
            }
        }

        stage('Análisis de Secretos (Gitleaks)') {
            steps {
                script {
                    // Ejecutar Gitleaks. --exit-code 0 evita que el pipeline falle aquí si encuentra algo
                    sh './gitleaks detect --source . --report-path gitleaks-report.json --exit-code 0'
                    
                    uploadToDefectDojo('Gitleaks Scan', 'gitleaks-report.json')
                }
            }
        }

        stage('Análisis SAST (Bandit)') {
            steps {
                script {
                    // 1. Reporte JSON para DefectDojo (sin romper build)
                    sh '. venv/bin/activate && bandit -r . -f json -o bandit-report.json --exit-zero'
                    
                    uploadToDefectDojo('Bandit Scan', 'bandit-report.json')

                    // 2. Security Gate (Romper build si hay criticos)
                    try {
                        echo "Ejecutando Security Gate de Bandit..."
                        // -lll (High Severity), -iii (High Confidence)
                        sh '. venv/bin/activate && bandit -r . -lll -iii'
                    } catch (Exception e) {
                        // Marcamos el build como inestable en lugar de fallido total, o error() para fallar
                        error("Security Gate SAST fallido: Se encontraron vulnerabilidades críticas.")
                    }
                }
            }
        }

        stage('Análisis SCA (Dependency-Track)') {
            steps {
                script {
                    // 1. Generar SBOM
                    sh '. venv/bin/activate && cyclonedx-py -r requirements.txt -o sbom.xml'

                    // 2. Subir a Dependency-Track (Plugin)
                    // Asegúrate de que el ID 'deptrack-api-key' contiene solo la API KEY, nada más.
                    dependencyTrackPublisher artifact: 'sbom.xml',
                        projectName: "${DT_PROJECT_NAME}",
                        projectVersion: "${DT_PROJECT_VERSION}",
                        synchronous: true,
                        dependencyTrackUrl: "${DT_URL}",
                        dependencyTrackApiKey: "${DT_API_KEY}", 
                        failedTotalCritical: 1,
                        failedTotalHigh: 1
                    
                    // Opcional: Subir también a DefectDojo
                    uploadToDefectDojo('CycloneDX Scan', 'sbom.xml')
                }
            }
        }
    }
    
    post {
        always {
            // Esto guardará los reportes visibles en Jenkins
            archiveArtifacts artifacts: '*.json, *.xml', allowEmptyArchive: true
            cleanWs()
        }
    }
}

// Función auxiliar
def uploadToDefectDojo(scanType, fileName) {
    echo "Subiendo reporte ${scanType} a DefectDojo..."
    // Verifica si el archivo existe antes de subir para evitar errores 404/500
    if (fileExists(fileName)) {
        sh """
            curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
            -H "Authorization: Token ${DOJO_API_KEY}" \
            -F "active=true" \
            -F "verified=true" \
            -F "scan_type=${scanType}" \
            -F "product_name=${DOJO_PRODUCT}" \
            -F "engagement_name=${DOJO_ENGAGEMENT}" \
            -F "file=@${fileName}"
        """
    } else {
        echo "Advertencia: El archivo ${fileName} no se generó, saltando subida a DefectDojo."
    }
}
