Add-Type -AssemblyName System.Drawing
$srcPath = "C:\Users\Ali.Asjad\.gemini\antigravity\brain\e65bebad-63cf-4301-bda8-52ddb8ea5cbc\safebrowse_icon_1774697730466.png"
$img = [System.Drawing.Image]::FromFile($srcPath)
$sizes = @(16, 48, 128)
$destDir1 = "e:\BSCS\Projects\With Arslan\GRE FYP WORK (SHA SAAB)\Yadhav (Real Time Browser Extension Security)\Working\extension\icons"
$destDir2 = "e:\BSCS\Projects\With Arslan\GRE FYP WORK (SHA SAAB)\Yadhav (Real Time Browser Extension Security)\Working\extension\dist\icons"

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s)
    $graph = [System.Drawing.Graphics]::FromImage($bmp)
    $graph.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graph.DrawImage($img, 0, 0, $s, $s)
    $bmp.Save("$destDir1\icon$s.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Save("$destDir2\icon$s.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $graph.Dispose()
    $bmp.Dispose()
}
$img.Dispose()
write-host "Resizing complete!"
