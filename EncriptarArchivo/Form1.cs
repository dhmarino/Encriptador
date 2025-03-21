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
                                //PgpEncrypt.EncryptFile(inputFilePath, outputFilePath, publicKeyPath);
                                using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                                using (Stream outputFileStream = File.Create(outputFilePath))
                                {
                                   PgpEncryptFile.EncryptFile(outputFileStream, inputFilePath, publicKeyStream, true, true);
                                }
                                MessageBox.Show("Se encriptó el archivo: " + inputFilePath + "\nCon la llave pública: " + openFileDialog1.SafeFileName);
                            }
                        }
                        else if (result == DialogResult.No)
                        {
                            // Encriptar todos los archivos juntos
                            PgpEncryptFile.EncryptFiles(inputFilePaths, publicKeyPath);
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
                            bool isVerified = PgpDecryptAndVerify.DecryptAndVerify(inputStream, keyStream, pubKeyStream, passphrase, outputFilePath);
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
    }
}
