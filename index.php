<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<title>Decodificar CSR</title>
	</head>
	<body>
		<h1>Decodificador de CSR</h1>
		<form action="" method="POST">
			<label for="txtcsr">Ingresa tu CSR:</label>
			<p><textarea required name="txtcsr" id="txtcsr" rows="6" cols="50" placeholder="-----BEGIN CERTIFICATE REQUEST-----" /></textarea></p>
			<p><input type="submit" name="decodeCSR" value="Enviar"/></p>
		</form>
	
<?php

set_include_path("./phpseclib");
include('File/X509.php');
include('Crypt/RSA.php');

if(isset($_POST['decodeCSR']))
{
	$micsr=$_POST['txtcsr'];
	$data=openssl_csr_get_subject($micsr);
	if ($data==true)
	{
		
		echo "<style type=\"text/css\">
.tg  {border-collapse:separate;border-spacing:0;border-color:#252850;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 10px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#252850;background-color:#e8edff;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 10px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:#252850;background-color:#b9c9fe;}
.tg .tg-1{background-color:#D2E4FC;font-weight:300;text-align:left;vertical-align:top}
.tg .tg-up{background-color:#444682;color:#ffffff;font-weight:700;text-align:left;vertical-align:top}
.tg .tg-up1{background-color:#444682;color:#ffffff;font-weight:700;text-align:left;vertical-align:top;border-radius: 10px 10px 0px 0px;}
.tg .tg-0{text-align:left;vertical-align:topfont-weight:300;}
.tg .tg-3{background-color:#ef8496;text-align:left;font-weight:300;vertical-align:top}
</style>
<br>
<table class=\"tg\" align=\"center\">
<colgroup>
<col style=\"width: 350px\">
<col style=\"width: 350px\">
</colgroup>
  <tr>
    <th class=\"tg-up1\" colspan=\"2\">Información del CSR:</th>
  </tr>";
		//llenar datos del subject
		
		echo "<tr><th class=\"tg-up\" colspan=\"2\">Sujeto:</th></tr>";
		
		$obs="";
		$enviarme="";
		$subj_cont=0;
		
		if (array_key_exists('CN',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Nombre Común:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['CN']."</td></tr>";$enviarme = $enviarme . "Nombre comun: " . $data['CN'] ."\r\n";}
		else {$obs = $obs."<b>Nombre Común</b> no puede estar vacío<br>";}
	
		if (array_key_exists('O',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Organización:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['O']."</td></tr>";$enviarme = $enviarme . "Organizacion: " . $data['O'] ."\r\n";}
		else {$obs = $obs."<b>Organización</b> no puede estar vacío<br>";}
	
		if (array_key_exists('OU',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Unidad Organizacional:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['OU']."</td></tr>";$enviarme = $enviarme . "Unidad Organizacional: " . $data['OU'] ."\r\n";}
		
		if (array_key_exists('L',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Localidad:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['L']."</td></tr>";$enviarme = $enviarme . "Localidad: " . $data['L'] ."\r\n";}
		else {$obs = $obs."<b>Localidad</b> no puede estar vacío<br>";}
	
		if (array_key_exists('ST',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Estado:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['ST']."</td></tr>";$enviarme = $enviarme . "Estado: " . $data['ST'] ."\r\n";}
		else {$obs = $obs."<b>Estado</b> no puede estar vacío<br>";}
	
		if (array_key_exists('C',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">País:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['C']."</td></tr>";$enviarme = $enviarme . "Pais: " . $data['C'] ."\r\n";}
		else {$obs = $obs."<b>País</b> no puede estar vacío<br>";}
	
		if (array_key_exists('emailAddress',$data))
		{$subj_cont++;echo "<tr><td class=\"tg-". $subj_cont%2 ."\">Correo:</td><td class=\"tg-". $subj_cont%2 ."\">".$data['emailAddress']."</td></tr>";$enviarme = $enviarme . "Correo: " . $data['emailAddress'] ."\r\n";}
		
		echo "<tr><th class=\"tg-up\" colspan=\"2\">Seguridad:</th></tr>";
	$x509 = new File_X509;
	$tcsr = $x509->loadCSR($micsr);	
		//datos del tipo de llave
		$llave= $tcsr['certificationRequestInfo']['subjectPKInfo']['algorithm']['algorithm'];
		
		if ($llave == "rsaEncryption")
		{
			$llave = "RSA";
		} else if ($llave == "id-dsa")
		{
			$llave = "DSA";
		} else if ($llave == "id-ecPublicKey")
		{
			$llave = "EC - Curva Elíptica";
		}
		
		echo "<tr><td class=\"tg-1\">Tipo de Llave:</td><td class=\"tg-1\">".$llave."</td></tr>";
		
		
		//datos del algoritmo de cifrado
		$alg = $tcsr['signatureAlgorithm']['algorithm'];
		
		$alg = str_replace('WithRSAEncryption',' con RSA',$alg);
		
		if (substr($alg,0,12) == "id-dsa-with-")
		{
			$alg = substr($alg,12)." con DSA";
		} else
		if (substr($alg,0,11) == "ecdsa-with-")
		{
			$alg = substr($alg,11)." con ECDSA";
		}
		

		if ( $alg == "2.16.840.1.101.3.4.3.1")
		{
			$alg = "sha224 con DSA";
		} else if ($alg == "2.16.840.1.101.3.4.3.2")
		{
			$alg = "sha256 con DSA";
		} else if ($alg == "2.16.840.1.101.3.4.3.3")
		{
			$alg = "sha384 con DSA";
		} else if ($alg == "2.16.840.1.101.3.4.3.4")
		{
			$alg = "sha512 con DSA";
		} else if ($alg == "1.3.36.3.3.1.3")
		{
			$alg = "RIPEMD-128 con RSA";
		} else if ($alg == "1.3.36.3.3.1.2")
		{
			$alg = "RIPEMD-160 con RSA";
		} else if ($alg == "1.3.36.3.3.1.4")
		{
			$alg = "RIPEMD-256 con RSA";
		} else if ($alg == "1.2.840.10045.4.3.1")
		{
			$alg = "SHA224 con ECDSA";
		} else if ($alg == "1.2.840.10045.4.3.4")
		{
			$alg = "SHA512 con ECDSA";
		} else if ($alg == "1.2.840.10045.4.3.2")
		{
			$alg = "SHA256 con ECDSA";
		} else if ($alg == "1.2.840.10045.4.3.3")
		{
			$alg = "SHA384 con ECDSA";
		}		
		
		echo "<tr><td class=\"tg-0\">Algoritmo de Cifrado:</td>";
		
		if (strtolower(substr($alg,0,4)) == "sha1")
		{
			$obs = $obs."El algoritmo de cifrado <b>sha1</b> no se permite para certificados SSL de una CA.<br>";
			echo "<td class=\"tg-3\">".$alg."</td></tr>";
		}else if (strtolower(substr($alg,0,2)) == "md")
		{
			$obs = $obs."El algoritmo de cifrado <b>".strtolower(substr($alg,0,3))."</b> no se permite para certificados SSL de una CA.<br>";
			echo "<td class=\"tg-3\">".$alg."</td></tr>";
		} else {echo "<td class=\"tg-0\">".$alg."</td></tr>";}
		
		if ($llave == "RSA")
		{
			//Tamaño de llave
			$pubkey = $tcsr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'];
			$rsa = new Crypt_RSA;
			$rsa->loadKey($pubkey);
			$rsa->setPublicKey();
			$publickey = $rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_OPENSSH);
			//echo substr($publickey,7,48);
			$datito = base64_decode(substr($publickey,7,48)); 
			$datito = implode(unpack("H*", $datito));
			$key_type_txt_size = intval(substr($datito,0,8))*2;
			$key_type_txt = substr($datito,8,$key_type_txt_size);
			$key_type_txt = pack("H*", $key_type_txt);
			//echo "Tamaño de Tipo de llave: ".$key_type_txt_size."<br>";
			//echo "Tipo de llave: ".$key_type_txt."<br>";
			$pub_exp_size = intval(substr($datito,8+$key_type_txt_size,8))*2;
			//echo $pub_exp = substr($datito,8+$key_type_txt_size+8,$pub_exp_size);
			//echo "Tamaño de Exp pub: ".$pub_exp_size."<br>";
			//echo "Exp pub: ".$pub_exp."<br>";
			$key_size = (hexdec(intval(substr($datito,8+$key_type_txt_size+8+$pub_exp_size,8)))-1)*8;
			echo "<tr><td class=\"tg-1\">Tamaño de llave:</td>";
			if ($key_size < 2048)
		{
			$obs =  $obs."El tamaño de llave mínimo debe ser de <b>2048</b> bits";
			echo "<td class=\"tg-3\">".$key_size."</td></tr>";
		} else {echo "<td class=\"tg-1\">".$key_size."</td></tr>";}
		}
		
		if ($obs != "")
		{
			echo "<tr><th class=\"tg-up\" colspan=\"2\">Observaciones:</th></tr>";
		
			echo "<tr><th class=\"tg-1\" colspan=\"2\">".$obs."</th></tr>";
		}
		
		echo "</table>";
		
$enviarme = $enviarme . "CSR: " . $micsr;
		
	}
	else if ($data==false)
	{
		echo 'No se pudo leer el CSR ingresado.';
	}
}
?>
	
	</body>
</html>
