using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System;
using System.Data;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using Org.BouncyCastle.Utilities.IO;
using System.Diagnostics;
using System.Reflection;
using System.IO.Compression;

namespace EncriptarArchivo
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            Assembly assembly = Assembly.GetExecutingAssembly();
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            labelVersion.Text = $"Versión:{ fvi.FileVersion}";
        }
        //Se probo para llave ECDSA/EdDSA y RSA
        public class PgpEncrypt
        {
            public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                using (Stream outputFileStream = File.Create(outputFilePath))
                {
                    EncryptFile(outputFileStream, inputFilePath, publicKeyStream, true, true);
                }
            }

            private static void EncryptFile(
                Stream outputStream,
                string fileName,
                Stream publicKeyStream,
                bool armor,
                bool withIntegrityCheck)
            {
                PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

                using (MemoryStream bOut = new MemoryStream())
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

                    using (Stream compressedOut = comData.Open(bOut))
                    {
                        PgpUtilities.WriteFileToLiteralData(
                            compressedOut,
                            PgpLiteralData.Binary,
                            new FileInfo(fileName));
                    } // Aquí se cierra el Stream directamente

                    PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                        SymmetricKeyAlgorithmTag.Cast5,
                        withIntegrityCheck,
                        new SecureRandom());

                    cPk.AddMethod(pubKey);

                    byte[] bytes = bOut.ToArray();

                    if (armor)
                    {
                        using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                        {
                            using (Stream cOut = cPk.Open(armoredStream, bytes.Length))
                            {
                                cOut.Write(bytes, 0, bytes.Length);
                            }
                        }
                    }
                    else
                    {
                        using (Stream cOut = cPk.Open(outputStream, bytes.Length))
                        {
                            cOut.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
            }

            private static PgpPublicKey ReadPublicKey(Stream inputStream)
            {
                using (Stream input = PgpUtilities.GetDecoderStream(inputStream))
                {
                    PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(input);
                    foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
                    {
                        foreach (PgpPublicKey k in kRing.GetPublicKeys())
                        {
                            if (k.IsEncryptionKey)
                            {
                                return k;
                            }
                        }
                    }
                }
                throw new ArgumentException("No encryption key found in public key.");
            }

            internal static void EncryptFiles(string[] inputFilePaths, string publicKeyPath)
            {
                // Mostrar un SaveFileDialog para seleccionar la ubicación y nombre del archivo ZIP
                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    saveFileDialog.Filter = "ZIP Files|*.zip";
                    saveFileDialog.Title = "Guardar archivo comprimido";
                    saveFileDialog.FileName = "ArchivosComprimidos.zip"; // Nombre predeterminado

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string zipPath = saveFileDialog.FileName;
                        string[] selectedFiles = inputFilePaths;

                        // Comprimir archivos en el ZIP sin usar CreateEntryFromFile
                        using (FileStream zipToOpen = new FileStream(zipPath, FileMode.Create))
                        using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Create))
                        {
                            foreach (string file in selectedFiles)
                            {
                                // Crear una entrada en el archivo ZIP
                                ZipArchiveEntry entry = archive.CreateEntry(Path.GetFileName(file));

                                // Copiar el contenido del archivo en la entrada del ZIP
                                using (FileStream fileToCompress = new FileStream(file, FileMode.Open, FileAccess.Read))
                                using (Stream entryStream = entry.Open())
                                {
                                    fileToCompress.CopyTo(entryStream);
                                }
                            }
                        }

                        //MessageBox.Show("Archivos comprimidos exitosamente en " + zipPath);
                        PgpEncrypt.EncryptFile(zipPath, zipPath + ".pgp", publicKeyPath);
                        File.Delete(zipPath);
                        MessageBox.Show("Se encriptaron todos los archivos juntos en: " + zipPath + ".pgp" + "\nCon la llave pública: " + publicKeyPath);
                    }
                }
            }
            
        }
        //Se probo para llave RSA y ECDSA/EdDSA
        public class PgpDecrypt
        {
            public static bool DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath, string passphrase)
            {
                using (Stream inputStream = File.OpenRead(inputFilePath))
                using (Stream keyIn = File.OpenRead(privateKeyPath))
                using (Stream outputStream = File.Create(outputFilePath))
                {
                    bool error = DecryptFile(inputStream, outputStream, keyIn, passphrase.ToCharArray());
                    return error;
                }
            }

            private static bool DecryptFile(
                Stream inputStream,
                Stream outputStream,
                Stream privateKeyStream,
                char[] passPhrase)
            {
                //Banderas
                bool error=false;
               
                inputStream = PgpUtilities.GetDecoderStream(inputStream);

                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                if (o is PgpEncryptedDataList list)
                {
                    enc = list;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }

                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
                
                    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
                    {
                        try
                        {
                            sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase);
                            if (sKey != null)
                            {
                                pbe = pked;
                                break;
                            }
                        }
                        catch (Exception)
                        {
                            MessageBox.Show("La contraseña es incorrecta");
                            error = true;
                            return error;
                        }
                    }
                
                    if (sKey == null)
                    {
                        throw new ArgumentException("La llave secreta no corresponde al archivo");
                    }
                    Stream clear = pbe.GetDataStream(sKey);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData cData)
                    {
                        PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                        message = pgpFact.NextPgpObject();
                    }

                    if (message is PgpLiteralData ld)
                    {
                        Stream unc = ld.GetInputStream();
                        Streams.PipeAll(unc, outputStream);
                    }
                    else if (message is PgpOnePassSignatureList)
                    {
                        throw new PgpException("Encrypted message contains a signed message - not literal data.");
                    }
                    else
                    {
                        throw new PgpException("Message is not a simple encrypted file - type unknown.");
                    }

                    if (pbe.IsIntegrityProtected() && !pbe.Verify())
                    {
                        throw new PgpException("Message failed integrity check.");
                    }
                    return  error;
                    
            }


            public static bool DecryptAndVerifyPgpFile(string inputFilePath, string outputFilePath, string privateKeyPath, string publicKeyPath, string passphrase)
            {
                using (Stream inputStream = File.OpenRead(inputFilePath))
                using (Stream privateKeyStream = File.OpenRead(privateKeyPath))
                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                using (Stream outputStream = File.Create(outputFilePath))
                {
                    bool error = DecryptAndVerifyFile(inputStream, outputStream, privateKeyStream, publicKeyStream, passphrase.ToCharArray());
                    return error;
                }
            }

            private static bool DecryptAndVerifyFile(
    Stream inputStream,
    Stream outputStream,
    Stream privateKeyStream,
    Stream publicKeyStream,
    char[] passPhrase)
            {
                bool error = false;

                try
                {
                    inputStream = PgpUtilities.GetDecoderStream(inputStream);

                    PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                    PgpEncryptedDataList enc;

                    PgpObject o = pgpF.NextPgpObject();
                    if (o is PgpEncryptedDataList list)
                    {
                        enc = list;
                    }
                    else
                    {
                        enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                    }

                    PgpPrivateKey sKey = null;
                    PgpPublicKeyEncryptedData pbe = null;
                    PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

                    foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
                    {
                        try
                        {
                            sKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase);
                            if (sKey != null)
                            {
                                pbe = pked;
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show("Error al encontrar la llave secreta: " + ex.Message);
                            error = true;
                            return error;
                        }
                    }

                    if (sKey == null)
                    {
                        throw new ArgumentException("La llave secreta no corresponde al archivo");
                    }

                    Stream clear = pbe.GetDataStream(sKey);
                    PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                    PgpObject message = plainFact.NextPgpObject();

                    if (message is PgpCompressedData cData)
                    {
                        PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());
                        message = pgpFact.NextPgpObject();
                    }

                    if (message is PgpLiteralData literalData)
                    {
                        Stream unc = literalData.GetInputStream();
                        Streams.PipeAll(unc, outputStream);
                    }
                    else if (message is PgpOnePassSignatureList opsl)
                    {
                        PgpOnePassSignature ops = opsl[0];
                        PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
                        PgpPublicKey pubKey = pgpPub.GetPublicKey(ops.KeyId);

                        PgpObject pgpObject = plainFact.NextPgpObject();
                        if (pgpObject is PgpLiteralData)
                        {
                            Console.WriteLine("Es un pgpLiteralData");
                            //PgpLiteralData signedLiteralData = (PgpLiteralData)pgpObject;
                            // Tu código aquí
                        }
                        else
                        {
                            // Manejo del error
                            Console.WriteLine("Error: Objeto inesperado en el flujo de datos.");
                        }

                        PgpLiteralData signedLiteralData = (PgpLiteralData)plainFact.NextPgpObject();
                        Stream dIn = signedLiteralData.GetInputStream();
                        ops.InitVerify(pubKey);

                        PgpSignatureList sigList = (PgpSignatureList)plainFact.NextPgpObject();
                        PgpSignature pgpSig = sigList[0];

                        int ch;
                        while ((ch = dIn.ReadByte()) >= 0)
                        {
                            ops.Update((byte)ch);
                        }

                        if (ops.Verify(pgpSig))
                        {
                            Streams.PipeAll(dIn, outputStream);
                            MessageBox.Show("Firma verificada correctamente.");
                        }
                        else
                        {
                            throw new PgpException("Firma no válida.");
                        }
                    }
                    else
                    {
                        throw new PgpException("Mensaje no es un archivo simple desencriptado - tipo desconocido.");
                    }

                    if (pbe.IsIntegrityProtected() && !pbe.Verify())
                    {
                        throw new PgpException("El mensaje falló la verificación de integridad.");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error durante el proceso de desencriptación y verificación: " + ex.Message);
                    error = true;
                }

                return error;
            }
            private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
            {
                PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

                if (pgpSecKey == null)
                {
                    return null;
                }

                return pgpSecKey.ExtractPrivateKey(pass);
            }
        }
        public class PgpKeyInfo
        {
            public static DateTime? GetKeyExpiration(string publicKeyPath)
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                {
                    PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                    foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                    {
                        foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                        {
                            DateTime creationTime = key.CreationTime;
                            long validityPeriod = key.GetValidSeconds(); // Validity period in seconds

                            if (validityPeriod == 0)
                            {
                                // The key does not expire
                                return null;
                            }
                            else
                            {
                                // Calculate the expiration time
                                DateTime expirationTime = creationTime.AddSeconds(validityPeriod);
                                return expirationTime;
                            }
                        }
                    }
                }
                throw new ArgumentException("No valid keys found in the public key file.");
            }
            public static long GetKeyId(string publicKeyPath)
            {
                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                {
                    PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                    foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                    {
                        foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                        {
                            long keyId = key.KeyId;
                            return (keyId);
                        }
                    }
                }
                throw new ArgumentException("No valid keys found in the public key file.");
            }
        }
        private void BtnEncriptar_Click(object sender, EventArgs e)
        {
            bool publicKey = false;
            string publicKeyPath = "";
            try
            {
                openFileDialog1.Filter = "Archivos de texto (*.txt)|*.txt|Todos los archivos(*.*)|*.*";
                openFileDialog1.Title = "Seleccione archivos para encriptar";
                openFileDialog1.Multiselect = true;

                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    string[] inputFilePaths = openFileDialog1.FileNames;

                    openFileDialog1.FileName = "";
                    openFileDialog1.Filter = "Llave Pública (*.asc)|*.asc|Todos los archivos(*.*)|*.*";
                    openFileDialog1.Title = "Seleccione la llave pública con la que quiere encriptar los archivos";

                    if (openFileDialog1.ShowDialog() == DialogResult.OK)
                    {
                        publicKeyPath = openFileDialog1.FileName;
                        publicKey = true;
                    }

                    if (publicKey)
                    {
                        DialogResult result = MessageBox.Show("¿Desea encriptar los archivos individualmente?", "Encriptar Archivos", MessageBoxButtons.YesNoCancel);

                        if (result == DialogResult.Yes)
                        {
                            // Encriptar archivos individualmente
                            foreach (string inputFilePath in inputFilePaths)
                            {
                                string outputFilePath = inputFilePath + ".pgp";
                                PgpEncrypt.EncryptFile(inputFilePath, outputFilePath, publicKeyPath);
                                MessageBox.Show("Se encriptó el archivo: " + inputFilePath + "\nCon la llave pública: " + openFileDialog1.SafeFileName);
                            }
                        }
                        else if (result == DialogResult.No)
                        {
                            // Encriptar todos los archivos juntos
                            PgpEncrypt.EncryptFiles(inputFilePaths, publicKeyPath);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void Desencriptar_Click(object sender, EventArgs e)
        {
            string inputFilePath = "C:\\Test\\pgp\\encrypted_output.pgp";
            string outputFilePath;
            string privateKeyPath = "C:\\Test\\pgp\\llave_ECDSA_SECRET.asc";
            string passphrase;

            bool inputfile = false;
            bool privateKey = false;
            string fileName = "";

            try
            {
                openFileDialog1.FileName = "";
                openFileDialog1.Filter = "Archivos PGP (*.pgp)|*.pgp|Todos los archivos(*.*)|*.*";
                openFileDialog1.Title = "Selecione un archivo para desencriptar";

                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    inputFilePath = openFileDialog1.FileName;
                    fileName = openFileDialog1.SafeFileName;
                    inputfile = true;
                }
                if (inputfile)
                {
                    openFileDialog1.FileName = "";
                    openFileDialog1.Filter = "Llave Privada (*.asc)|*.asc|Todos los archivos(*.*)|*.*";
                    openFileDialog1.Title = "Selecione la llave privada con la que quiere desencriptar el archivo";
                    if (openFileDialog1.ShowDialog() == DialogResult.OK)
                    {
                        privateKeyPath = openFileDialog1.FileName;
                        privateKey = true;
                    }
                    outputFilePath = inputFilePath.ToLower().Replace(".pgp","");
                    if (privateKey)
                    {
                        FormClave nuevaVentana = new FormClave(); // Abrimos formulario para que el usuario ingreses la passphrase
                        nuevaVentana.ShowDialog();
                        passphrase = nuevaVentana.ValorIngresado;
                        bool error = PgpDecrypt.DecryptFile(inputFilePath, outputFilePath, privateKeyPath, passphrase);
                        if (!error)
                        {
                            MessageBox.Show("Se desencripto el archivo: " + fileName + "\nCon la llave Privada: " + openFileDialog1.SafeFileName);
                        }
                    }
                }        
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }    
            
        }
        private void BtnVerificarVencimiento_Click(object sender, EventArgs e)
        {
            string publicKeyPath = "C:\\Test\\pgp\\llave_ECDSA_public.asc";
            bool publicKey = false;
            try
            {
                openFileDialog1.FileName = "";
                openFileDialog1.Filter = "Llave Publica (*.asc)|*.asc|Todos los archivos(*.*)|*.*";
                openFileDialog1.Title = "Selecione la llave publica de la que quiere saber la fecha de expiracion";
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    publicKeyPath = openFileDialog1.FileName;
                    publicKey = true;
                }
                if (publicKey)
                {
                    DateTime? expirationDate = PgpKeyInfo.GetKeyExpiration(publicKeyPath);

                    if (expirationDate.HasValue)
                    {
                        MessageBox.Show("La Llave " + openFileDialog1.SafeFileName + " expira el: " + expirationDate.Value.ToString("dd/MM/yyyy"));
                    }
                    else
                    {
                        MessageBox.Show("La Llave no expira");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void BtnKeyId_Click(object sender, EventArgs e)
        {
            string publicKeyPath = "";
            bool publicKey = false;
            try
            {
                openFileDialog1.FileName = "";
                openFileDialog1.Filter = "Llave Publica (*.asc)|*.asc|Todos los archivos(*.*)|*.*";
                openFileDialog1.Title = "Selecione la llave publica de la que quiere saber el Key ID";
                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    publicKeyPath = openFileDialog1.FileName;
                    publicKey = true;
                }
                if (publicKey)
                {
                    long KeyId = PgpKeyInfo.GetKeyId(publicKeyPath);
                    MessageBox.Show("Key ID: " + KeyId.ToString("X"));
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void BtnDesencriptarVerificar_Click(object sender, EventArgs e)
        {
            string inputFilePath = @"C:\Desarrollo\01_Clientes\AMEX\TestJcop5\GIPVLDART.H.DLY.20241106.053402.pgp";
            string outputFilePath;
            string privateKeyFilePath = @"C:\Desarrollo\01_Clientes\AMEX\TestJcop5\Valid_test_encryption_key_Feb2024_0x185D5457_SECRET.asc";
            string publicKeyFilePath = @"C:\Desarrollo\01_Clientes\AMEX\TestJcop5\Amex_Test_Signing Key_ValidARG_12Feb2024.txt";
            string passphrase;

            bool inputfile = false;
            bool privateKey = false;
            bool publicKey = false;
            string fileName;

            try
            {
                openFileDialog1.FileName = "";
                openFileDialog1.Filter = "Archivos PGP (*.pgp)|*.pgp|Todos los archivos(*.*)|*.*";
                openFileDialog1.Title = "Seleccione un archivo para desencriptar";

                if (openFileDialog1.ShowDialog() == DialogResult.OK)
                {
                    inputFilePath = openFileDialog1.FileName;
                    fileName = openFileDialog1.SafeFileName;
                    inputfile = true;
                }
                if (inputfile)
                {
                    openFileDialog1.FileName = "";
                    openFileDialog1.Filter = "Llave Privada (*.asc)|*.asc|Todos los archivos(*.*)|*.*";
                    openFileDialog1.Title = "Seleccione la llave privada con la que quiere desencriptar el archivo";
                    if (openFileDialog1.ShowDialog() == DialogResult.OK)
                    {
                        privateKeyFilePath = openFileDialog1.FileName;
                        privateKey = true;
                    }
                    openFileDialog1.FileName = "";
                    openFileDialog1.Filter = "Llave Pública (*.txt)|*.txt|Todos los archivos(*.*)|*.*";
                    openFileDialog1.Title = "Seleccione la llave pública para verificar la firma";
                    if (openFileDialog1.ShowDialog() == DialogResult.OK)
                    {
                        publicKeyFilePath = openFileDialog1.FileName;
                        publicKey = true;
                    }
                    outputFilePath = inputFilePath.ToLower().Replace(".pgp", "");
                    if (privateKey && publicKey)
                    {
                        FormClave nuevaVentana = new FormClave(); // Abrimos formulario para que el usuario ingrese la passphrase
                        nuevaVentana.ShowDialog();
                        passphrase = nuevaVentana.ValorIngresado;
                        using (Stream inputStream = File.OpenRead(inputFilePath))
                        using (Stream keyStream = File.OpenRead(privateKeyFilePath))
                        using (Stream pubKeyStream = File.OpenRead(publicKeyFilePath))
                        {
                            bool isVerified = DecryptAndVerify(inputStream, keyStream, pubKeyStream, passphrase, outputFilePath);
                            MessageBox.Show(isVerified ? "Firma válida y archivo desencriptado." : "Firma no válida, pero archivo desencriptado.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private bool DecryptAndVerify(Stream encryptedData, Stream privateKeyStream, Stream publicKeyStream, string passphrase, string outputFilePath)
        {
            bool Verify = false;
            
            PgpObjectFactory pgpF = new PgpObjectFactory(PgpUtilities.GetDecoderStream(encryptedData));
            PgpEncryptedDataList encDataList = null;
            PgpObject o;

            while ((o = pgpF.NextPgpObject()) != null)
            {
                if (o is PgpEncryptedDataList list)
                {
                    encDataList = list;
                    break;
                }
            }

            if (encDataList == null)
                throw new ArgumentException("No se encontraron datos encriptados.");

            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData encryptedDataObj = null;
            PgpSecretKeyRingBundle pgpSecBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            foreach (PgpPublicKeyEncryptedData pked in encDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>())
            {
                privateKey = FindSecretKey(pgpSecBundle, pked.KeyId, passphrase.ToCharArray());

                if (privateKey != null)
                {
                    encryptedDataObj = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Clave privada incorrecta o no encontrada.");

            using (Stream clearStream = encryptedDataObj.GetDataStream(privateKey))
            {
                PgpOnePassSignatureList onePassSignatures = null;
                PgpLiteralData literalData = null;
                
                PgpObjectFactory plainFact = new PgpObjectFactory(clearStream);
                PgpObject message;
                try
                {
                    while ((message = plainFact.NextPgpObject()) != null)
                    {
                        Console.WriteLine($"Objeto encontrado: {message.GetType().Name}");

                        if (message is PgpCompressedData compressed)
                        {
                            PgpObjectFactory decompressedFactory = new PgpObjectFactory(compressed.GetDataStream());
                            PgpObject innerMessage;

                            while ((innerMessage = decompressedFactory.NextPgpObject()) != null)
                            {
                                Console.WriteLine($"Objeto dentro de la compresión: {innerMessage.GetType().Name}");

                                if (innerMessage is PgpOnePassSignatureList onePassList)
                                    onePassSignatures = onePassList;

                                if (innerMessage is PgpLiteralData innerLiteral)
                                {
                                    literalData = innerLiteral;
                                    break;  // ⚠️ Salimos del loop una vez que encontramos PgpLiteralData
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error al procesar el archivo PGP: {ex.Message}");
                }
               

                // Verificar firma después de encontrar PgpLiteralData
                if (onePassSignatures != null && literalData != null)
                {
                    Console.WriteLine("Se encontró la firma y los datos. Procediendo a verificar...");
                    using (Stream outputStream = File.Create(outputFilePath))
                    using (Stream literalStream = literalData.GetInputStream())
                    {
                              Streams.PipeAll(literalStream, outputStream);
                    }
                    Verify = VerifySignature(publicKeyStream, onePassSignatures, plainFact);
                }
                else
                {
                    Console.WriteLine("No se encontró firma en el archivo.");
                }
            }
            return Verify;
        }
        private bool VerifySignature(Stream publicKeyStream, PgpOnePassSignatureList onePassSignatures, PgpObjectFactory plainFact)
        {
            PgpPublicKeyRingBundle pgpPubBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));
            PgpOnePassSignature onePassSignature = onePassSignatures[0];
            PgpPublicKey pubKey = pgpPubBundle.GetPublicKey(onePassSignature.KeyId) ?? throw new Exception("Clave pública para verificar la firma no encontrada.");
            try
            {
                onePassSignature.InitVerify(pubKey);

                PgpObject literalDataObj = plainFact.NextPgpObject();
                if (literalDataObj is PgpLiteralData literalData)
                {
                    using (Stream dIn = literalData.GetInputStream())
                    {
                        int ch;
                        while ((ch = dIn.ReadByte()) >= 0)
                            onePassSignature.Update((byte)ch);
                    }
                }
                return true;
            }
            catch (Exception)
            {
                throw new Exception("No se pudo verificar la firma.");
            }
        }
        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] passPhrase)
        {
            PgpSecretKey secretKey = pgpSec.GetSecretKey(keyId);
            return secretKey?.ExtractPrivateKey(passPhrase);
        }
    }
}
