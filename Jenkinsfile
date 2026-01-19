pipeline {
  agent any
  stages {
    stage('Preparaci�n') {
      steps {
        sh 'python3 -m venv venv'
        sh '. venv/bin/activate && pip install -r requirements.txt'
        sh '. venv/bin/activate && pip install bandit cyclonedx-bom requests'
        sh 'curl -sS https://github.com/zricethezav/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz | tar xz gitleaks'
      }
    }

    stage('An�lisis de Secretos (Gitleaks)') {
      steps {
        script {
          sh './gitleaks detect --source . --report-path gitleaks-report.json --exit-code 0'

          // Subir a DefectDojo
          uploadToDefectDojo('Gitleaks Scan', 'gitleaks-report.json')
        }

      }
    }

    stage('An�lisis SAST (Bandit)') {
      steps {
        script {
          sh '. venv/bin/activate'

          // 1. Ejecutar para reporte (JSON) sin romper el build aún
          sh '. venv/bin/activate && bandit -r . -f json -o bandit-report.json --exit-zero'

          // 2. Subir a DefectDojo
          uploadToDefectDojo('Bandit Scan', 'bandit-report.json')

          // 3. Security Gate: Fallar si hay vulnerabilidades ALTAS (-lll)
          // -lll = nivel de severidad alto
          // -iii = nivel de confianza alto
          try {
            sh '. venv/bin/activate && bandit -r . -lll -iii'
          } catch (Exception e) {
            error("Security Gate SAST fallido: Se encontraron vulnerabilidades críticas/altas en el código.")
          }
        }

      }
    }

    stage('An�lisis SCA (Dependency-Track)') {
      steps {
        script {
          sh '. venv/bin/activate && cyclonedx-py -r requirements.txt -o sbom.xml'

          // 2. Subir a Dependency-Track y Aplicar Gate
          // Se recomienda usar el plugin oficial de Jenkins "Dependency-Track" para facilitar el gate
          // Si usas el plugin:
          dependencyTrackPublisher artifact: 'sbom.xml',
          projectName: "${DT_PROJECT_NAME}",
          projectVersion: "${DT_PROJECT_VERSION}",
          synchronous: true,
          dependencyTrackUrl: "${DT_URL}",
          dependencyTrackApiKey: "${DT_API_KEY}",
          // Security Gate: Fallar si hay vulns Críticas o Altas
          failedTotalCritical: 1,
          failedTotalHigh: 1

          // Nota: Dependency-Track se encargará de analizar el SBOM contra su base de datos.
          // Si prefieres ver esto también en DefectDojo, puedes importar el SBOM allá también:
          uploadToDefectDojo('CycloneDX Scan', 'sbom.xml')
        }

      }
    }

  }
  environment {
    DOJO_URL = 'http://tu-defectdojo-server:8080'
    DOJO_PRODUCT = 'PyGoat'
    DOJO_ENGAGEMENT = 'Jenkins CI Scan'
    DOJO_API_KEY = credentials('defectdojo-api-key')
    DT_URL = 'http://tu-deptrack-server:8081'
    DT_API_KEY = credentials('deptrack-api-key')
    DT_PROJECT_NAME = 'PyGoat'
    DT_PROJECT_VERSION = '1.0.0'
  }
  post {
    always {
      archiveArtifacts(artifacts: '*.json, *.xml', allowEmptyArchive: true)
      cleanWs()
    }

  }
}