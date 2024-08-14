namespace EncriptarArchivo
{
    partial class Form1
    {
        /// <summary>
        /// Variable del diseñador necesaria.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Limpiar los recursos que se estén usando.
        /// </summary>
        /// <param name="disposing">true si los recursos administrados se deben desechar; false en caso contrario.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Código generado por el Diseñador de Windows Forms

        /// <summary>
        /// Método necesario para admitir el Diseñador. No se puede modificar
        /// el contenido de este método con el editor de código.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.BtnEncriptar = new System.Windows.Forms.Button();
            this.BtnDesencriptar = new System.Windows.Forms.Button();
            this.BtnVerificarVencimiento = new System.Windows.Forms.Button();
            this.BtnKeyId = new System.Windows.Forms.Button();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.labelVersion = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // BtnEncriptar
            // 
            this.BtnEncriptar.Location = new System.Drawing.Point(240, 79);
            this.BtnEncriptar.Margin = new System.Windows.Forms.Padding(4);
            this.BtnEncriptar.Name = "BtnEncriptar";
            this.BtnEncriptar.Size = new System.Drawing.Size(292, 90);
            this.BtnEncriptar.TabIndex = 0;
            this.BtnEncriptar.Text = "Encriptar";
            this.BtnEncriptar.UseVisualStyleBackColor = true;
            this.BtnEncriptar.Click += new System.EventHandler(this.BtnEncriptar_Click);
            // 
            // BtnDesencriptar
            // 
            this.BtnDesencriptar.Location = new System.Drawing.Point(240, 233);
            this.BtnDesencriptar.Margin = new System.Windows.Forms.Padding(4);
            this.BtnDesencriptar.Name = "BtnDesencriptar";
            this.BtnDesencriptar.Size = new System.Drawing.Size(292, 90);
            this.BtnDesencriptar.TabIndex = 1;
            this.BtnDesencriptar.Text = "Desencriptar";
            this.BtnDesencriptar.UseVisualStyleBackColor = true;
            this.BtnDesencriptar.Click += new System.EventHandler(this.Desencriptar_Click);
            // 
            // BtnVerificarVencimiento
            // 
            this.BtnVerificarVencimiento.Location = new System.Drawing.Point(240, 385);
            this.BtnVerificarVencimiento.Margin = new System.Windows.Forms.Padding(4);
            this.BtnVerificarVencimiento.Name = "BtnVerificarVencimiento";
            this.BtnVerificarVencimiento.Size = new System.Drawing.Size(292, 90);
            this.BtnVerificarVencimiento.TabIndex = 2;
            this.BtnVerificarVencimiento.Text = "Verificar Vencimiento";
            this.BtnVerificarVencimiento.UseVisualStyleBackColor = true;
            this.BtnVerificarVencimiento.Click += new System.EventHandler(this.BtnVerificarVencimiento_Click);
            // 
            // BtnKeyId
            // 
            this.BtnKeyId.Location = new System.Drawing.Point(240, 540);
            this.BtnKeyId.Margin = new System.Windows.Forms.Padding(4);
            this.BtnKeyId.Name = "BtnKeyId";
            this.BtnKeyId.Size = new System.Drawing.Size(292, 90);
            this.BtnKeyId.TabIndex = 3;
            this.BtnKeyId.Text = "KeyId";
            this.BtnKeyId.UseVisualStyleBackColor = true;
            this.BtnKeyId.Click += new System.EventHandler(this.BtnKeyId_Click);
            // 
            // labelVersion
            // 
            this.labelVersion.AutoSize = true;
            this.labelVersion.Font = new System.Drawing.Font("Modern No. 20", 10.125F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.labelVersion.Location = new System.Drawing.Point(591, 670);
            this.labelVersion.Name = "labelVersion";
            this.labelVersion.Size = new System.Drawing.Size(178, 29);
            this.labelVersion.TabIndex = 4;
            this.labelVersion.Text = "Versión: 1.0.0.0";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 719);
            this.Controls.Add(this.labelVersion);
            this.Controls.Add(this.BtnKeyId);
            this.Controls.Add(this.BtnVerificarVencimiento);
            this.Controls.Add(this.BtnDesencriptar);
            this.Controls.Add(this.BtnEncriptar);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(4);
            this.Name = "Form1";
            this.Text = "PGP Soluciones";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button BtnEncriptar;
        private System.Windows.Forms.Button BtnDesencriptar;
        private System.Windows.Forms.Button BtnVerificarVencimiento;
        private System.Windows.Forms.Button BtnKeyId;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Label labelVersion;
    }
}

