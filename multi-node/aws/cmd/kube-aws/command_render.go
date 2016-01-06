package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"text/template"

	"github.com/coreos/coreos-kubernetes/multi-node/aws/pkg/cluster"
	"github.com/coreos/coreos-kubernetes/multi-node/aws/pkg/tlsutil"
	"github.com/spf13/cobra"
)

var (
	cmdRender = &cobra.Command{
		Use:   "render",
		Short: "Render a CloudFormation template",
		Long:  ``,
		Run:   runCmdRender,
	}

	renderOpts struct {
		ConfigPath string
	}
	kubeconfigTemplate *template.Template
)

func init() {
	kubeconfigTemplate = template.Must(template.New("kubeconfig").Parse(kubeconfigTemplateContents))

	cmdRoot.AddCommand(cmdRender)
	cmdRender.Flags().StringVar(&renderOpts.ConfigPath, "config", "./cluster.yaml", "Path to config yaml file")
}

func runCmdRender(cmd *cobra.Command, args []string) {
	cfg := cluster.NewDefaultConfig()
	err := cluster.DecodeConfigFromFile(cfg, renderOpts.ConfigPath)
	if err != nil {
		stderr("Unable to load cluster config: %v", err)
		os.Exit(1)
	}

	if rootOpts.AssetDir == "" {
		stderr("--asset-dir option is not specified")
		os.Exit(1)
	}
	if err := initAssetDirectory(cfg); err != nil {
		stderr("Error initializing asset directory: %v", err)
		os.Exit(1)
	}
}

func initAssetDirectory(cfg *cluster.Config) error {
	if _, err := os.Stat(rootOpts.AssetDir); err == nil {
		return fmt.Errorf("Asset directory %s already exists!", rootOpts.AssetDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("Error stat-ing asset directory path %s: %v", rootOpts.AssetDir, err)
	}

	if err := os.Mkdir(rootOpts.AssetDir, 0700); err != nil {
		return fmt.Errorf("Error creating assets directory %s: %v", rootOpts.AssetDir, err)
	}

	inCfg, err := os.Open(renderOpts.ConfigPath)
	if err != nil {
		return err
	}
	defer inCfg.Close()

	outCfgPath := filepath.Join(rootOpts.AssetDir, "cluster.yaml")
	outCfg, err := os.OpenFile(outCfgPath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer outCfg.Close()

	if _, err := io.Copy(outCfg, inCfg); err != nil {
		return fmt.Errorf("Error copying config: %v", err)
	}

	credentialsDir := filepath.Join(rootOpts.AssetDir, "credentials")
	if err := os.Mkdir(credentialsDir, 0700); err != nil {
		return fmt.Errorf("Error creating credentials directory %s: %v", credentialsDir, err)
	}

	if err := initTLS(cfg, credentialsDir); err != nil {
		return fmt.Errorf("Failed initializing TLS infrastructure: %v", err)
	}

	cfg.TLSConfig.ReadFilesFromPaths()

	fmt.Println("Initialized TLS infrastructure")

	cloudConfigDir := filepath.Join(rootOpts.AssetDir, "cloud-config")
	if err := os.Mkdir(cloudConfigDir, 0700); err != nil {
		return fmt.Errorf("Error creating cloud-config directory %s: %v", cloudConfigDir, err)
	}

	//Now it's time to template the cloudconfig files
	if err := templateCloudConfigs(cfg, cloudConfigDir); err != nil {
		return err
	}

	fmt.Println("Templated cloud-config files")

	tmpl, err := cluster.StackTemplateBody(cloudConfigDir)
	if err != nil {
		return fmt.Errorf("Failed to generate template: %v", err)
	}

	templatePath := filepath.Join(rootOpts.AssetDir, "template.json")
	if err := ioutil.WriteFile(templatePath, []byte(tmpl), 0600); err != nil {
		return fmt.Errorf("Failed writing output to %s: %v", templatePath, err)
	}

	fmt.Println("Generated cloudformation template")

	kubeconfig, err := newKubeconfig(cfg)
	if err != nil {
		return fmt.Errorf("Failed rendering kubeconfig: %v", err)
	}

	kubeconfigPath := path.Join(credentialsDir, "kubeconfig")
	if err := ioutil.WriteFile(kubeconfigPath, kubeconfig, 0600); err != nil {
		return fmt.Errorf("Failed writing kubeconfig to %s: %v", kubeconfigPath, err)
	}

	fmt.Printf("Wrote kubeconfig to %s\n", kubeconfigPath)

	return nil
}

func templateCloudConfigs(cfg *cluster.Config, cloudConfigDir string) error {

	for _, role := range []string{"controller", "worker"} {
		inpath := filepath.Join("artifacts", "cloud-config", role)
		outpath := filepath.Join(cloudConfigDir, role)

		out, err := os.OpenFile(outpath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("error opening %s: %v", outpath, err)
		}
		defer out.Close()

		tmpl, err := template.New(path.Base(inpath)).ParseFiles(inpath)
		if err != nil {
			return err
		}

		if err := tmpl.Execute(out, cfg); err != nil {
			return err
		}
	}

	return nil
}

func initTLS(cfg *cluster.Config, tlsDir string) error {
	cfg.TLSConfig = cluster.NewTLSConfig(tlsDir)

	caConfig := tlsutil.CACertConfig{
		CommonName:   "kube-ca",
		Organization: "kube-aws",
	}
	caKey, caCert, err := initTLSCA(caConfig, cfg.TLSConfig.CAKeyFile, cfg.TLSConfig.CACertFile)
	if err != nil {
		return err
	}

	apiserverConfig := tlsutil.ServerCertConfig{
		CommonName: "kube-apiserver",
		DNSNames: []string{
			"kubernetes",
			"kubernetes.default",
			"kubernetes.default.svc",
			"kubernetes.default.svc.cluster.local",
			cfg.ExternalDNSName,
		},
		IPAddresses: []string{
			cfg.ControllerIP,
			cfg.KubernetesServiceIP,
		},
	}
	if err := initTLSServer(apiserverConfig, caCert, caKey, cfg.TLSConfig.APIServerKeyFile, cfg.TLSConfig.APIServerCertFile); err != nil {
		return err
	}

	workerConfig := tlsutil.ClientCertConfig{
		CommonName: "kube-worker",
		DNSNames: []string{
			"*.*.compute.internal",
			"*.ec2.internal",
		},
	}
	if err := initTLSClient(workerConfig, caCert, caKey, cfg.TLSConfig.WorkerKeyFile, cfg.TLSConfig.WorkerCertFile); err != nil {
		return err
	}

	adminConfig := tlsutil.ClientCertConfig{
		CommonName: "kube-admin",
	}
	if err := initTLSClient(adminConfig, caCert, caKey, cfg.TLSConfig.AdminKeyFile, cfg.TLSConfig.AdminCertFile); err != nil {
		return err
	}

	return nil
}

func initTLSCA(cfg tlsutil.CACertConfig, keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	cert, err := tlsutil.NewSelfSignedCACertificate(cfg, key)
	if err != nil {
		return nil, nil, err
	}

	if err := writeKey(keyPath, key); err != nil {
		return nil, nil, err
	}
	if err := writeCert(certPath, cert); err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func initTLSServer(cfg tlsutil.ServerCertConfig, caCert *x509.Certificate, caKey *rsa.PrivateKey, keyPath, certPath string) error {
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return err
	}

	cert, err := tlsutil.NewSignedServerCertificate(cfg, key, caCert, caKey)
	if err != nil {
		return err
	}

	if err := writeKey(keyPath, key); err != nil {
		return err
	}
	if err := writeCert(certPath, cert); err != nil {
		return err
	}

	return nil
}

func initTLSClient(cfg tlsutil.ClientCertConfig, caCert *x509.Certificate, caKey *rsa.PrivateKey, keyPath, certPath string) error {
	key, err := tlsutil.NewPrivateKey()
	if err != nil {
		return err
	}

	cert, err := tlsutil.NewSignedClientCertificate(cfg, key, caCert, caKey)
	if err != nil {
		return err
	}

	if err := writeKey(keyPath, key); err != nil {
		return err
	}
	if err := writeCert(certPath, cert); err != nil {
		return err
	}

	return nil
}

func writeCert(certPath string, cert *x509.Certificate) error {
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return tlsutil.WriteCertificatePEMBlock(f, cert)
}

func writeKey(keyPath string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer f.Close()

	return tlsutil.WritePrivateKeyPEMBlock(f, key)
}

func newKubeconfig(cfg *cluster.Config) ([]byte, error) {
	data := struct {
		ClusterName       string
		APIServerEndpoint string
		AdminCertFile     string
		AdminKeyFile      string
		CACertFile        string
	}{
		ClusterName:       cfg.ClusterName,
		APIServerEndpoint: fmt.Sprintf("https://%s", cfg.ExternalDNSName),
		AdminCertFile:     "admin.pem",
		AdminKeyFile:      "admin-key.pem",
		CACertFile:        "ca.pem",
	}

	var rendered bytes.Buffer
	if err := kubeconfigTemplate.Execute(&rendered, data); err != nil {
		return nil, err
	}

	return rendered.Bytes(), nil
}

var kubeconfigTemplateContents = `apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: {{ .CACertFile }}
    server: {{ .APIServerEndpoint }}
  name: kube-aws-{{ .ClusterName }}-cluster
contexts:
- context:
    cluster: kube-aws-{{ .ClusterName }}-cluster
    namespace: default
    user: kube-aws-{{ .ClusterName }}-admin
  name: kube-aws-{{ .ClusterName }}-context
users:
- name: kube-aws-{{ .ClusterName }}-admin
  user:
    client-certificate: {{ .AdminCertFile }}
    client-key: {{ .AdminKeyFile }}
current-context: kube-aws-{{ .ClusterName }}-context
`
