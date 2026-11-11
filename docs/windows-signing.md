# Firma de Windows

El workflow firma los ejecutables de Windows con Azure Artifact Signing antes de
empaquetarlos y calcular sus hashes. Comprueba la arquitectura PE, la firma de
TECNO BROS STUDIOS, S.L. y el sello de tiempo. Si falla, no publica la versión.
La implementación está en [sign-windows.ps1](../scripts/sign-windows.ps1).

Cada repositorio tiene su propia identidad OIDC, con permiso para firmar únicamente
en el perfil de certificados asignado. El entorno `windows-signing` solo admite
`main`; las pull requests no reciben sus secrets. Los seis valores `AZURE_*`
se guardan cifrados en ese entorno. No hay claves privadas, contraseñas de Azure
ni certificados exportados en el código o en los artefactos.

La configuración sigue la [autenticación OIDC de Azure](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect).
El nombre del editor y el certificado público forman parte de cualquier ejecutable
firmado y pueden consultarse desde Windows.

Para comprobar un build sin publicar, ejecuta el workflow manualmente con
`dry_run: true`. La variable `BATTLY_COMPONENT_RELEASE_PUBLISH_ENABLED` permite
detener la publicación sin desactivar las compilaciones ni la firma. Una versión
ya publicada se conserva; para distribuir otros bytes hay que cambiar su versión.

El cliente y el servidor se firman en x64, x86 y ARM64. El workflow verifica los
hashes originales antes de firmar y actualiza los seis hashes de Windows después
de verificar las firmas. Comprueba también que los binarios de Linux y macOS
no han cambiado. Véase [signed-manifest.cjs](../scripts/signed-manifest.cjs).
