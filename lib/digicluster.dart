import './linux_can/linux_can.dart';
import './main.dart';

class DigiCluster {
  final canDevice = CanDevice(bitrate: 500000);

  void Read_CAN() {
    canDevice.setup();
    while (true) {
      //Read a CAN frame from the buffer (filtered to 7xx and any other broadcasts)
      final frame = canDevice.read();

      //if CAN ID matches 7xx, send it to the another function(await) for parsing (we'll set it up to parse specific UDS responses from there)
      if (frame.id == 0x7E8) {
        //MyHomePage.state(frame.id.toString());
      }

      //if CAN ID matches broadcast data, send it to

    }
  }
}
