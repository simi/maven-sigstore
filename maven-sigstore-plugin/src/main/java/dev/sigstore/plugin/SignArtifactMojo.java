package dev.sigstore.plugin;

import javax.inject.Inject;

import java.io.File;
import java.io.IOException;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

import io.takari.jpgp.PgpArtifactSigner;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.file.Files.copy;
import static java.nio.file.Files.createDirectories;

@Mojo( name = "signArtifact", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true )
public class SignArtifactMojo extends AbstractMojo
{
    public static final String SIGNATURE_EXTENSION = ".asc";
    private static final Logger logger = LoggerFactory.getLogger( SignArtifactMojo.class );

    @Inject
    protected MavenProjectHelper projectHelper;

    /**
     * Reference to maven project; will be used to find JAR file to be signed unless
     * specified in input-jar
     */
    @Parameter( defaultValue = "${project}", readonly = true, required = true )
    private MavenProject project;

    @Parameter( property = "gpg.skip", defaultValue = "false" )
    private boolean skip;

    @Parameter( property = "gpg.passphrase" )
    private String passphrase;

    @Override
    public void execute() throws MojoExecutionException
    {

        List<SigningBundle> signingBundles = new ArrayList<>();

        if ( !"pom".equals( project.getPackaging() ) )
        {
            //
            // Artifact
            //
            org.apache.maven.artifact.Artifact artifact = project.getArtifact();
            File file = artifact.getFile();
            if ( file == null )
            {
                logger.info( "There is no artifact present. Make sure you run this after the package phase." );
                return;
            }
            File projectArtifactSignature = sign( file );
            if ( projectArtifactSignature != null )
            {
                signingBundles.add(
                        new SigningBundle( artifact.getArtifactHandler().getExtension(), projectArtifactSignature ) );
            }
        }

        //
        // POM
        //
        File pomToSign = new File( project.getBuild().getDirectory(), project.getBuild().getFinalName() + ".pom" );
        try
        {
            createDirectories( pomToSign.getParentFile().toPath() );
            copy( project.getFile().toPath(), pomToSign.toPath(), StandardCopyOption.REPLACE_EXISTING );
        }
        catch ( IOException e )
        {
            throw new MojoExecutionException( "Error copying POM for signing.", e );
        }
        File pomSignature = sign( pomToSign );
        if ( pomSignature != null )
        {
            signingBundles.add( new SigningBundle( "pom", pomSignature ) );
        }

        //
        // Attached artifact signatures
        //
        for ( org.apache.maven.artifact.Artifact a : project.getAttachedArtifacts() )
        {
            File signatureFile = sign( a.getFile() );
            if ( signatureFile != null )
            {
                signingBundles.add( new SigningBundle( a.getArtifactHandler().getExtension(),
                        signatureFile, a.getClassifier() ) );
            }
        }

        for ( SigningBundle bundle : signingBundles )
        {
            projectHelper.attachArtifact( project, bundle.getExtension() + SIGNATURE_EXTENSION,
                    bundle.getClassifier(), bundle.getSignature() );
        }
    }

    private File sign( File file ) throws MojoExecutionException
    {
        try
        {
            PgpArtifactSigner signer = new PgpArtifactSigner();
            if ( passphrase != null )
            {
                return signer.sign( file, passphrase );
            }
            else
            {
                return signer.sign( file );
            }
        }
        catch ( Exception e )
        {
            throw new MojoExecutionException( "Error signing artifact " + file + ".", e );
        }
    }
}
