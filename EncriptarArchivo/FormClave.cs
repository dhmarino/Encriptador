using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EncriptarArchivo
{
    public partial class FormClave : Form
    {
        public FormClave()
        {
            InitializeComponent();
        }
        public string ValorIngresado { get; set; }

        private void FormClave_Load(object sender, EventArgs e)
        {
            
        }

        private void BtnOk_Click(object sender, EventArgs e)
        {
            ValorIngresado = textBox1.Text;
            this.Close(); // Cierra la ventana actual
        }
    }
}
