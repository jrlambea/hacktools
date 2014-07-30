/******************************************************************************

    This code is the very first try to make a real KeyGenMaker template, this
    is very simple for now:

    - A only main function.

    The idea is create a proces capable to make a Keygen in 3 steps:

    - Design the form in glade.
    - Code the algorithm in a simple GUI.
    - Make the Keygen only pressing a single button.

    The key in that process is make a good template to permit the parser
    understand all XML fields and fill all information correctly.

                                                            Enjoy & Hack'a'lot
                                                     with ♥ jr_lambea 30/07/14

******************************************************************************/
using Gtk;

int main (string[] args) {     

    // Initialize the gtk environment
    Gtk.init (ref args);
    
    // Builder is the class that creates a interface from a XML
    var builder = new Builder ();

    // Importing the glade file
    builder.add_from_file (##TPL_FILE##);
    builder.connect_signals (null);

    // Get object imports the attributes from the glade/XML
    var window = builder.get_object ("window1") as Window;

    // Ends the app process when the "Close window" Gtk Button is pressed
    window.destroy.connect (Gtk.main_quit);

    var entry1 = builder.get_object ("entry1") as Entry;
    var entry2 = builder.get_object ("entry2") as Entry;
    var button = builder.get_object ("button1") as Button;
    
    button.clicked.connect (() => {
        ##ALGORITHM##
    });

    window.show_all ();
    Gtk.main ();

    return 0;

}
